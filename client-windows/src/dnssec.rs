//! Validation DNSSEC côté client Windows (mission 12).
//!
//! Le service ne se fie plus au bit AD : chaque réponse passe par
//! `hickory-proto` (bibliothèque DNSSEC reconnue), qui construit la chaîne
//! DS/DNSKEY jusqu'aux ancres racine compilées et vérifie les signatures. La
//! requête initiale et les requêtes de validation empruntent le même POST DoH
//! via Tor.
//!
//! Aucune donnée de requête n'est journalisée ; seules les erreurs de
//! validation remontent au relais, qui répond SERVFAIL sans nom de domaine.

use std::pin::Pin;
use std::sync::Arc;

use futures::stream::{self, Stream};
use hickory_proto::error::ProtoError;
use hickory_proto::op::Message;
use hickory_proto::rr::dnssec::rdata::DNSSECRData;
use hickory_proto::rr::dnssec::rdata::NSEC3;
use hickory_proto::rr::dnssec::{Algorithm, PublicKeyEnum, TrustAnchor};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::xfer::{DnsHandle, DnsRequest, DnsResponse, DnssecDnsHandle};

use crate::doh::ClientDoh;

/// Adaptateur synchrone : chaque requête DNS de la chaîne est un POST DoH
/// distinct, comme une requête utilisateur. Le flux est immédiat, sans runtime
/// asynchrone supplémentaire.
#[derive(Clone)]
struct DoHHandle {
    doh: Arc<ClientDoh>,
}

impl DnsHandle for DoHHandle {
    type Response = Pin<Box<dyn Stream<Item = Result<DnsResponse, ProtoError>> + Send + Unpin>>;
    type Error = ProtoError;

    fn is_verifying_dnssec(&self) -> bool {
        true
    }

    fn send<R: Into<DnsRequest> + Unpin + Send + 'static>(&self, request: R) -> Self::Response {
        let request = request.into();
        let resultat = request
            .to_vec()
            .map_err(ProtoError::from)
            .and_then(|brut| self.doh.poster(&brut).map_err(ProtoError::from))
            .and_then(|brut| Message::from_vec(&brut).map_err(ProtoError::from))
            .and_then(DnsResponse::from_message);
        Box::pin(stream::iter(vec![resultat]))
    }
}

/// Valide `requete` et retourne la réponse authentifiée, ré-encodée depuis le
/// message validé. Gère les zones non signées en prouvant l'absence de DS par
/// NSEC/NSEC3 (comme le client Linux) avant d'accepter une réponse non signée.
/// Jamais d'acceptation sans preuve.
pub fn resoudre(doh: &ClientDoh, requete: &[u8]) -> Result<Vec<u8>, String> {
    let message = Message::from_vec(requete).map_err(|e| e.to_string())?;
    valider(
        DoHHandle {
            doh: Arc::new(doh.clone()),
        },
        message,
        ancres_racine(),
    )
}

/// Clé publique de KSK-2024 (key tag 38696), au format DNSKEY brut (RFC 3110).
/// Son empreinte SHA-256 a été recalculée et comparée à celle de l'IANA
/// (683D2D0A…FB2B16, data.iana.org/root-anchors/root-anchors.xml) le 24/11/2026.
const KSK_2024: &[u8] = include_bytes!("ancres/38696.rsa");

/// Les ancres de la racine : celles de hickory 0.24 (19036, 20326) PLUS KSK-2024.
/// La racine n'est plus signée que par 38696 depuis le 11/10/2026 : sans elle, plus
/// rien ne validait (relecture du 24/11, point 1, même défaut que le client Linux).
/// KSK-2017 (20326) est révoquée le 11/01/2027 ; surveiller le prochain roulement.
fn ancres_racine() -> TrustAnchor {
    let mut ancre = TrustAnchor::default();
    if let Ok(cle) = PublicKeyEnum::from_public_bytes(KSK_2024, Algorithm::RSASHA256) {
        ancre.insert_trust_anchor(&cle);
    }
    ancre
}

fn valider<H>(handle: H, message: Message, ancre: TrustAnchor) -> Result<Vec<u8>, String>
where
    H: DnsHandle<Error = ProtoError> + Clone + 'static,
{
    let question = message
        .queries()
        .first()
        .cloned()
        .ok_or_else(|| "requête sans question".to_string())?;
    let nœud = DnssecDnsHandle::with_trust_anchor(handle.clone(), ancre.clone());
    let mut flux = nœud.send(DnsRequest::from(message.clone()));
    let reponse = match futures::executor::block_on(futures::StreamExt::next(&mut flux)) {
        Some(Ok(reponse)) => reponse,
        Some(Err(e)) => {
            // hickory refuse une réponse sans RRSIG avant tout autre contrôle :
            // une zone sans DS n'a pourtant rien à signer. Prouver l'absence de
            // DS chez le parent, puis servir la réponse reçue, limitée à la zone
            // prouvée. Sans preuve, le refus de hickory est conservé.
            return accepter_non_signee(&handle, &ancre, &message)
                .map_err(|motif| format!("validation DNSSEC : {e} ; {motif}"));
        }
        None => return Err("validation DNSSEC sans réponse".to_string()),
    };
    // Le message brut, tel que le nœud l'a envoyé : on y lit les RRSIG pour les
    // contrôles que la bibliothèque ne fait pas (voir `controler`).
    let brut = Message::from_vec(reponse.as_buffer()).map_err(|e| e.to_string())?;
    // LE MESSAGE VALIDÉ, JAMAIS LE BUFFER. hickory retire du message les RRset qui
    // n'ont pas vérifié mais garde le buffer d'origine intact : `into_buffer()`
    // relayait donc la réponse du nœud sans filtrage (relecture du 24/11, point 4a).
    let mut valide = reponse.into_message();
    controler(&question, &valide, &brut, maintenant_unix())?;
    // Une réponse d'une zone signée peut porter, après un CNAME, les
    // enregistrements d'une zone non signée : hickory les a retirés faute de
    // signature à vérifier. Ils ne reviennent que sur preuve d'absence de DS.
    completer_zone_non_signee(&handle, &ancre, &brut, &mut valide)?;
    valide.to_vec().map_err(|e| e.to_string())
}

/// Ce que le parent répond d'une délégation, après validation de sa réponse DS.
#[derive(Debug, PartialEq, Eq)]
enum Delegation {
    /// Un DS existe : la zone enfant est signée, une réponse non signée est une forgerie.
    Signee,
    /// NSEC du parent au nom de l'enfant, annonçant NS mais pas DS : zone non signée.
    SansDs,
    /// Rien de concluant (nom ordinaire, NSEC3 que hickory 0.24 ne valide pas...).
    Indetermine,
}

/// Interroge le parent pour le DS de `nom` et rend ce que sa réponse **validée**
/// prouve. Un DS présent prouve une zone signée ; un NSEC au nom de la délégation
/// qui annonce NS sans DS prouve une zone non signée. Tout le reste est
/// indéterminé : rien n'est déduit d'une réponse non validée.
fn delegation<H>(handle: &H, ancre: &TrustAnchor, nom: &Name) -> Delegation
where
    H: DnsHandle<Error = ProtoError> + Clone + 'static,
{
    let mut requete = Message::new();
    requete.add_query(hickory_proto::op::Query::query(nom.clone(), RecordType::DS));
    requete.set_recursion_desired(true);
    let nœud = DnssecDnsHandle::with_trust_anchor(handle.clone(), ancre.clone());
    let mut flux = nœud.send(DnsRequest::from(requete));
    let reponse = match futures::executor::block_on(futures::StreamExt::next(&mut flux)) {
        Some(Ok(reponse)) => reponse.into_message(),
        _ => return Delegation::Indetermine,
    };
    if reponse
        .answers()
        .iter()
        .any(|rr| rr.record_type() == RecordType::DS && rr.name().eq_case(nom))
    {
        return Delegation::Signee;
    }
    let nsec = reponse.name_servers().iter().find_map(|rr| {
        if rr.record_type() != RecordType::NSEC || !rr.name().eq_case(nom) {
            return None;
        }
        match rr.data() {
            Some(RData::DNSSEC(DNSSECRData::NSEC(nsec))) => Some(nsec),
            _ => None,
        }
    });
    match nsec {
        Some(nsec)
            if nsec.type_bit_maps().contains(&RecordType::NS)
                && !nsec.type_bit_maps().contains(&RecordType::DS) =>
        {
            Delegation::SansDs
        }
        _ => Delegation::Indetermine,
    }
}

/// Chemin de secours quand le validateur refuse une réponse non signée :
///
/// 1. remonter les labels du nom demandé et demander le DS de chacun au parent ;
///    un DS prouve une zone signée (refus conservé), un NSEC NS-sans-DS prouve
///    une zone non signée ;
/// 2. servir la réponse reçue, réduite à la question et aux enregistrements de
///    la zone prouvée non signée — aucun RRset d'une autre zone ne la traverse.
///
/// Le nom d'une zone non signée n'est authentifié par aucune signature : ce
/// chemin ne fait que constater qu'il n'existe rien à vérifier. Toute preuve
/// absente ou ambiguë laisse le refus de hickory intact.
fn accepter_non_signee<H>(
    handle: &H,
    ancre: &TrustAnchor,
    message: &Message,
) -> Result<Vec<u8>, String>
where
    H: DnsHandle<Error = ProtoError> + Clone + 'static,
{
    let question = message
        .queries()
        .first()
        .cloned()
        .ok_or_else(|| "requête sans question".to_string())?;
    let mut nom = question.name().clone();
    let mut zone = None;
    while !nom.is_root() {
        match delegation(handle, ancre, &nom) {
            Delegation::Signee => return Err("réponse non signée dans une zone signée".to_string()),
            Delegation::SansDs => {
                zone = Some(nom.clone());
                break;
            }
            Delegation::Indetermine => {}
        }
        nom = nom.base_name();
    }
    let zone = zone.ok_or_else(|| "réponse non signée sans preuve d'absence de DS".to_string())?;

    let mut flux = handle.clone().send(DnsRequest::from(message.clone()));
    let brute = futures::executor::block_on(futures::StreamExt::next(&mut flux))
        .ok_or_else(|| "aucune réponse du nœud".to_string())?
        .map_err(|e| format!("lecture de la réponse : {e}"))?
        .into_message();

    let mut sortie = Message::new();
    sortie.set_id(brute.id());
    sortie.set_message_type(brute.message_type());
    sortie.set_op_code(brute.op_code());
    sortie.set_response_code(brute.response_code());
    sortie.set_authoritative(brute.authoritative());
    for q in message.queries() {
        sortie.add_query(q.clone());
    }
    for rr in brute.answers() {
        if zone.zone_of(rr.name()) {
            sortie.add_answer(rr.clone());
        }
    }
    if sortie.response_code() == hickory_proto::op::ResponseCode::NoError
        && sortie.answers().is_empty()
    {
        return Err("réponse non signée vide".to_string());
    }
    sortie.to_vec().map_err(|e| e.to_string())
}

/// Remet dans le message validé les réponses que hickory a retirées parce
/// qu'elles n'ont aucune signature à vérifier — typiquement l'enregistrement
/// d'une zone non signée atteint par un CNAME depuis une zone signée.
///
/// Rien n'est remis sans la même preuve que `accepter_non_signee` : l'absence de
/// DS de la zone de l'enregistrement est demandée au parent par le validateur.
/// Un DS (zone signée) ou une preuve indéterminée laisse le filtrage de hickory
/// intact : la réponse reste amputée, jamais complétée par une donnée non
/// prouvée. Seule la section réponse est reprise ; les RRSIG ne sont jamais
/// recopiés.
fn completer_zone_non_signee<H>(
    handle: &H,
    ancre: &TrustAnchor,
    brut: &Message,
    valide: &mut Message,
) -> Result<(), String>
where
    H: DnsHandle<Error = ProtoError> + Clone + 'static,
{
    let mut retires: Vec<Record> = Vec::new();
    for rr in brut.answers() {
        if rr.record_type() == RecordType::RRSIG {
            continue;
        }
        let retenu = valide
            .answers()
            .iter()
            .any(|v| v.record_type() == rr.record_type() && v.name().eq_case(rr.name()));
        let deja = retires
            .iter()
            .any(|d| d.record_type() == rr.record_type() && d.name().eq_case(rr.name()));
        if !retenu && !deja {
            retires.push(rr.clone());
        }
    }
    if retires.is_empty() {
        return Ok(());
    }

    for rr in retires {
        let nom = rr.name().clone();
        let mut zone = None;
        let mut courant = nom.clone();
        while !courant.is_root() {
            match delegation(handle, ancre, &courant) {
                Delegation::Signee => {
                    return Err("réponse non signée dans une zone signée".to_string())
                }
                Delegation::SansDs => {
                    zone = Some(courant);
                    break;
                }
                Delegation::Indetermine => {}
            }
            courant = courant.base_name();
        }
        let zone =
            zone.ok_or_else(|| "réponse non signée sans preuve d'absence de DS".to_string())?;
        for brut_rr in brut.answers() {
            if brut_rr.record_type() == RecordType::RRSIG
                || brut_rr.record_type() != rr.record_type()
                || !brut_rr.name().eq_case(&nom)
                || !zone.zone_of(brut_rr.name())
            {
                continue;
            }
            valide.add_answer(brut_rr.clone());
        }
    }
    Ok(())
}

/// Vérifie si la réponse correspond à une zone non signée (délégation sans DS prouvée
/// par NSEC/NSEC3). Retourne `Ok(true)` si la zone est prouvée non signée.
fn est_zone_non_signee(
    question: &hickory_proto::op::Query,
    valide: &Message,
    brut: &Message,
) -> Result<bool, String> {
    use hickory_proto::rr::RecordType;

    use hickory_proto::op::ResponseCode;

    let nom_question = question.name();

    // Une réponse NÉGATIVE (NXDOMAIN ou NODATA, reconnaissable à sa SOA) n'est
    // pas une délégation non signée : ses preuves sont signées et doivent
    // passer les contrôles de signature, horloge comprise. Sans cette garde,
    // un NSEC de NODATA sans DS faisait accepter la réponse comme « zone non
    // signée » et sautait le contrôle de validité.
    let a_soa = valide
        .name_servers()
        .iter()
        .any(|r| r.record_type() == RecordType::SOA);
    if valide.response_code() == ResponseCode::NXDomain || a_soa {
        return Ok(false);
    }

    // Si la réponse a des réponses valides signées, ce n'est pas une zone non signée
    let a_reponses_signees = valide.answers().iter().any(|r| {
        r.record_type() != RecordType::RRSIG
            && (r.record_type() == question.query_type() || r.record_type() == RecordType::CNAME)
    });
    if a_reponses_signees {
        return Ok(false);
    }

    // La preuve doit figurer dans le message que le validateur a RETENU : un
    // enregistrement présent seulement dans le buffer brut n'a pas été validé.
    // Vérifier en plus la couverture, sans quoi n'importe quel NSEC/NSEC3 de la
    // section autorité suffirait à faire passer une zone signée pour non signée.
    for rr in valide.name_servers() {
        let nom_rr = rr.name();
        match rr.data() {
            Some(RData::DNSSEC(DNSSECRData::NSEC(nsec))) => {
                if nsec.type_bit_maps().contains(&RecordType::DS) {
                    // La zone annonce une délégation signée : pas de zone non signée.
                    continue;
                }
                if nsec_couvre(nom_rr, nsec.next_domain_name(), nom_question)
                    && preuve_presente_brut(brut, nom_rr, RecordType::NSEC)
                {
                    return Ok(true);
                }
            }
            Some(RData::DNSSEC(DNSSECRData::NSEC3(nsec3))) => {
                if nsec3.type_bit_maps().contains(&RecordType::DS) {
                    continue;
                }
                // NSEC3 : le nom demandé est haché, puis l'enregistrement doit
                // couvrir cette empreinte. L'opt-out seul ne prouve rien.
                if nsec3.opt_out()
                    && nsec3_couvre(nsec3, nom_rr, nom_question)?
                    && preuve_presente_brut(brut, nom_rr, RecordType::NSEC3)
                {
                    return Ok(true);
                }
            }
            _ => {}
        }
    }
    Ok(false)
}

/// Ordre canonique RFC 4034 : un NSEC couvre `nom` s'il en est le propriétaire ou
/// si `nom` tombe strictement entre le propriétaire et le nom suivant.
fn nsec_couvre(proprietaire: &Name, suivant: &Name, nom: &Name) -> bool {
    if nom.eq_case(proprietaire) || nom == proprietaire {
        return true;
    }
    if suivant <= proprietaire {
        return false;
    }
    nom > proprietaire && nom < suivant
}

/// Vrai si l'empreinte NSEC3 de `nom` tombe dans l'intervalle couvert par
/// l'enregistrement NSEC3 dont le propriétaire est `proprietaire`.
fn nsec3_couvre(nsec3: &NSEC3, proprietaire: &Name, nom: &Name) -> Result<bool, String> {
    let empreinte = nsec3
        .hash_algorithm()
        .hash(nsec3.salt(), nom, nsec3.iterations())
        .map_err(|e| format!("NSEC3 : empreinte de {nom} incalculable : {e}"))?;
    let hache = base32hex(empreinte.as_ref());
    let debut = premier_label(proprietaire);
    let fin = base32hex(nsec3.next_hashed_owner_name());
    // Base32hex : l'alphabet 0-9A-V est croissant en ASCII, la comparaison de
    // chaînes suffit donc une fois les labels normalisés en majuscules.
    if hache == debut || hache == fin {
        return Ok(true);
    }
    if fin <= debut {
        // Dernier maillon de la chaîne : il couvre jusqu'au début.
        return Ok(hache > debut || hache < fin);
    }
    Ok(hache > debut && hache < fin)
}

/// Premier label d'un nom, en majuscules et sans point final.
fn premier_label(nom: &Name) -> String {
    let texte = nom.to_ascii().trim_end_matches('.').to_uppercase();
    texte.split('.').next().unwrap_or("").to_string()
}

/// Encodage base32hex (RFC 4648 §7) d'une empreinte NSEC3, sans remplissage.
fn base32hex(octets: &[u8]) -> String {
    const ALPHABET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";
    let mut sortie = String::new();
    let mut tampon: u32 = 0;
    let mut bits = 0u32;
    for octet in octets {
        tampon = (tampon << 8) | u32::from(*octet);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            sortie.push(ALPHABET[((tampon >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        sortie.push(ALPHABET[((tampon << (5 - bits)) & 0x1f) as usize] as char);
    }
    sortie
}

/// Vrai si l'enregistrement (nom, type) existe aussi dans le buffer brut : un
/// enregistrement fabriqué par le validateur ne compte pas comme preuve reçue.
fn preuve_presente_brut(brut: &Message, nom: &Name, type_rr: RecordType) -> bool {
    brut.name_servers()
        .iter()
        .any(|r| r.record_type() == type_rr && (r.name() == nom || r.name().eq_case(nom)))
}

/// Vrai si le message retenu contient la SOA de la zone du nom demandé.
fn zone_autoritaire(nom: &Name, valide: &Message) -> bool {
    valide
        .name_servers()
        .iter()
        .any(|rr| rr.record_type() == RecordType::SOA && rr.name().zone_of(nom))
}

/// NODATA : le nom existe, le type demandé non. Preuve exigée dans le message
/// retenu : la SOA de la zone et un NSEC AU NOM DEMANDÉ dont le bitmap
/// n'annonce pas le type. Un NSEC d'un autre nom ne prouve rien.
fn nodata_prouve(question: &hickory_proto::op::Query, valide: &Message) -> bool {
    if !zone_autoritaire(question.name(), valide) {
        return false;
    }
    valide.name_servers().iter().any(|rr| {
        rr.record_type() == RecordType::NSEC
            && rr.name().eq_case(question.name())
            && rr
                .data()
                .and_then(RData::as_dnssec)
                .and_then(DNSSECRData::as_nsec)
                .is_some_and(|nsec| !nsec.type_bit_maps().contains(&question.query_type()))
    })
}

/// NXDOMAIN : hickory 0.24 vérifie la couverture NSEC et l'absence de wildcard
/// avant de rendre le message ; on exige en plus que la preuve soit RETENUE et
/// que la SOA de la zone soit présente. Les réponses négatives NSEC3, que
/// hickory ne sait pas valider, restent refusées : rien n'est accepté sans
/// preuve vérifiée.
fn nxdomain_prouve(question: &hickory_proto::op::Query, valide: &Message) -> bool {
    zone_autoritaire(question.name(), valide)
        && valide
            .name_servers()
            .iter()
            .any(|rr| rr.record_type() == RecordType::NSEC)
}

/// Tolérance d'horloge sur la validité des signatures : un poste peut dériver,
/// mais une tolérance large rouvrirait le rejeu de chaînes archivées.
const DERIVE_HORLOGE_S: i64 = 300;

fn maintenant_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Les contrôles que `hickory-proto` 0.24 ne fait pas, et sans lesquels « validé »
/// ne veut rien dire (relecture du 24/11, points 4a, 4b, 4c) :
/// - le message validé répond encore à la question (sinon le filtrage a tout
///   retiré : une réponse creuse n'est pas une réponse) ;
/// - TOUTE signature qui couvre un enregistrement retenu a été faite par la zone
///   de cet enregistrement ou par un de ses ancêtres (comparaison de labels) :
///   sans ce contrôle, le titulaire de n'importe quel domaine signé pouvait
///   « valider » une réponse pour n'importe quel nom ;
/// - et elle est dans sa période de validité, à la dérive d'horloge près.
/// Toutes les signatures, pas une : on ne sait pas laquelle hickory a retenue, et
/// exiger qu'elles passent toutes ne peut pas affaiblir la validation.
///
/// Si la réponse est une zone non signée prouvée (NSEC/NSEC3 opt-out), on l'accepte.
fn controler(
    question: &hickory_proto::op::Query,
    valide: &Message,
    brut: &Message,
    maintenant: i64,
) -> Result<(), String> {
    use hickory_proto::op::ResponseCode;
    use hickory_proto::rr::RecordType;

    // D'abord vérifier si c'est une zone non signée prouvée
    if let Ok(true) = est_zone_non_signee(question, valide, brut) {
        // Zone non signée prouvée par NSEC/NSEC3 : acceptée
        return Ok(());
    }

    if valide.response_code() == ResponseCode::NoError {
        let repond = valide.answers().iter().any(|r| {
            r.name().eq_case(question.name()) || r.name() == question.name()
        } && (r.record_type() == question.query_type() || r.record_type() == RecordType::CNAME));
        if !repond && !nodata_prouve(question, valide) {
            return Err("réponse validée vide pour la question posée".into());
        }
    } else if valide.response_code() == ResponseCode::NXDomain && !nxdomain_prouve(question, valide)
    {
        return Err("NXDOMAIN sans preuve d'inexistence retenue".into());
    }
    for r in valide.answers().iter().chain(valide.name_servers()) {
        if r.record_type() == RecordType::RRSIG {
            continue;
        }
        for sig in brut
            .answers()
            .iter()
            .chain(brut.name_servers())
            .filter(|s| s.name() == r.name())
            .filter_map(|s| {
                s.data()
                    .and_then(|d| d.as_dnssec())
                    .and_then(|d| d.as_rrsig())
            })
            .filter(|s| s.type_covered() == r.record_type())
        {
            if !sig.signer_name().zone_of(r.name()) {
                return Err("signature faite hors de la zone du nom signé".into());
            }
            let debut = sig.sig_inception() as i64;
            let fin = sig.sig_expiration() as i64;
            if maintenant + DERIVE_HORLOGE_S < debut || maintenant - DERIVE_HORLOGE_S > fin {
                return Err("signature hors de sa période de validité".into());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Query, ResponseCode};
    use hickory_proto::rr::dnssec::rdata::{DNSSECRData, DNSKEY, RRSIG};
    use hickory_proto::rr::dnssec::{tbs, Algorithm, KeyPair, PublicKeyEnum, SigSigner};
    use hickory_proto::rr::rdata::SOA;
    use hickory_proto::rr::{Name, RData, Record, RecordType};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn maintenant() -> u32 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0)
    }

    fn record_signe(nom: &Name, rrset: Vec<Record>, signer: &SigSigner) -> Record {
        record_signe_par(
            nom,
            nom,
            rrset,
            signer,
            maintenant() - 60,
            maintenant() + 3600,
        )
    }

    /// Signe `rrset` (au nom `nom`) avec la clé de `signer`, en annonçant
    /// `signataire` comme nom de signataire et la période donnée.
    fn record_signe_par(
        nom: &Name,
        signataire: &Name,
        rrset: Vec<Record>,
        signer: &SigSigner,
        debut: u32,
        fin: u32,
    ) -> Record {
        let rrsig = RRSIG::new(
            rrset[0].record_type(),
            Algorithm::ED25519,
            nom.num_labels(),
            rrset[0].ttl(),
            fin,
            debut,
            signer.calculate_key_tag().unwrap(),
            signataire.clone(),
            vec![],
        );
        let sig: Record<RRSIG> = Record::from_rdata(nom.clone(), rrset[0].ttl(), rrsig.clone());
        let tbs = tbs::rrset_tbs_with_rrsig(&sig, &rrset).unwrap();
        let octets = signer.sign(&tbs).unwrap();
        let signee = RRSIG::new(
            rrset[0].record_type(),
            Algorithm::ED25519,
            nom.num_labels(),
            rrset[0].ttl(),
            fin,
            debut,
            signer.calculate_key_tag().unwrap(),
            signataire.clone(),
            octets,
        );
        Record::from_rdata(
            nom.clone(),
            rrset[0].ttl(),
            RData::DNSSEC(DNSSECRData::RRSIG(signee)),
        )
    }

    #[derive(Clone)]
    struct FauxHandle {
        zone: Name,
        dnskey: DNSKEY,
        dns_reponse: Vec<u8>,
        dnskey_reponse: Vec<u8>,
        alterer: bool,
    }

    impl DnsHandle for FauxHandle {
        type Response = Pin<Box<dyn Stream<Item = Result<DnsResponse, ProtoError>> + Send + Unpin>>;
        type Error = ProtoError;

        fn send<R: Into<DnsRequest> + Unpin + Send + 'static>(&self, request: R) -> Self::Response {
            let q = request.into();
            let question = q.queries().first().cloned().unwrap();
            let brut = if question.query_type() == RecordType::DNSKEY {
                self.dnskey_reponse.clone()
            } else if question.query_type() == RecordType::A {
                let mut m = Message::from_vec(&self.dns_reponse).unwrap();
                if self.alterer {
                    for r in m.answers_mut() {
                        if let Some(RData::A(ref mut a)) = r.data_mut() {
                            *a = hickory_proto::rr::rdata::A::new(203, 0, 113, 9);
                        }
                    }
                }
                m.to_vec().unwrap()
            } else {
                Vec::new()
            };
            let resultat = Message::from_vec(&brut)
                .map_err(ProtoError::from)
                .and_then(DnsResponse::from_message);
            Box::pin(stream::iter(vec![resultat]))
        }
    }

    fn fixture() -> (FauxHandle, TrustAnchor) {
        let (h, a, _) = fixture_complete();
        (h, a)
    }

    fn fixture_complete() -> (FauxHandle, TrustAnchor, SigSigner) {
        let zone = Name::parse("example.test.", None).unwrap();
        let rng = ring::rand::SystemRandom::new();
        let graine = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let privee = ring::signature::Ed25519KeyPair::from_pkcs8(graine.as_ref()).unwrap();
        let cle = KeyPair::from_ed25519(privee);
        let signer = SigSigner::dnssec(
            cle.to_dnskey(Algorithm::ED25519).unwrap(),
            cle,
            zone.clone(),
            std::time::Duration::from_secs(3600),
        );
        let dnskey = signer.to_dnskey().unwrap();
        let dnskey_rr = Record::from_rdata(
            zone.clone(),
            3600,
            RData::DNSSEC(DNSSECRData::DNSKEY(dnskey.clone())),
        );
        let mut dnskeys = Message::new();
        dnskeys.add_query(hickory_proto::op::Query::query(
            zone.clone(),
            RecordType::DNSKEY,
        ));
        dnskeys.add_answer(dnskey_rr.clone());
        dnskeys.add_answer(record_signe(&zone, vec![dnskey_rr], &signer));

        let a = Record::from_rdata(
            zone.clone(),
            60,
            RData::A(hickory_proto::rr::rdata::A::new(192, 0, 2, 1)),
        );
        let mut reponse = Message::new();
        reponse.add_query(hickory_proto::op::Query::query(zone.clone(), RecordType::A));
        reponse.add_answer(a.clone());
        reponse.add_answer(record_signe(&zone, vec![a], &signer));

        let publique =
            PublicKeyEnum::from_public_bytes(dnskey.public_key(), Algorithm::ED25519).unwrap();
        let mut ancre = TrustAnchor::new();
        ancre.insert_trust_anchor(&publique);
        (
            FauxHandle {
                zone,
                dnskey,
                dns_reponse: reponse.to_vec().unwrap(),
                dnskey_reponse: dnskeys.to_vec().unwrap(),
                alterer: false,
            },
            ancre,
            signer,
        )
    }

    fn a(nom: &Name, octet: u8) -> Record {
        Record::from_rdata(
            nom.clone(),
            60,
            RData::A(hickory_proto::rr::rdata::A::new(192, 0, 2, octet)),
        )
    }

    fn question(nom: &Name) -> Message {
        let mut q = Message::new();
        q.add_query(hickory_proto::op::Query::query(nom.clone(), RecordType::A));
        q
    }

    /// Relecture du 24/11, point 4a : une adresse forgée, sans signature, à laquelle
    /// le nœud joint la DNSKEY d'ancrage (une constante publique). hickory accepte
    /// un RRset fait uniquement de clés d'ancrage sans vérifier de signature, et
    /// `into_buffer()` relayait alors l'adresse forgée.
    /// Mission 28, point 4 : verdict au vocabulaire du fichier de cas commun.
    fn classer(validation: Result<Vec<u8>, String>) -> &'static str {
        if validation.is_ok() {
            "accept"
        } else {
            "reject"
        }
    }

    #[test]
    fn adresse_forgee_portee_par_la_cle_d_ancrage_refusee() {
        let verdict = verdict_adresse_forgee();
        assert_eq!(verdict, "reject", "adresse forgée relayée");
    }

    fn verdict_adresse_forgee() -> &'static str {
        let (mut h, ancre, _) = fixture_complete();
        let mut forge = question(&h.zone);
        forge.add_answer(a(&h.zone, 66));
        forge.add_answer(Record::from_rdata(
            h.zone.clone(),
            3600,
            RData::DNSSEC(DNSSECRData::DNSKEY(h.dnskey.clone())),
        ));
        h.dns_reponse = forge.to_vec().unwrap();
        classer(valider(h.clone(), question(&h.zone), ancre))
    }

    /// Point 4b : la zone example.test. signe une adresse pour victime.test. avec sa
    /// propre clé, parfaitement valide. Le signataire n'est ni le nom signé ni un de
    /// ses ancêtres : refus.
    #[test]
    fn signature_d_une_autre_zone_refusee() {
        let verdict = verdict_autre_zone();
        assert_eq!(verdict, "reject", "signature hors zone acceptée");
    }

    fn verdict_autre_zone() -> &'static str {
        let (mut h, ancre, signer) = fixture_complete();
        let victime = Name::parse("victime.test.", None).unwrap();
        let enr = a(&victime, 77);
        let mut rep = question(&victime);
        rep.add_answer(enr.clone());
        rep.add_answer(record_signe_par(
            &victime,
            &h.zone,
            vec![enr],
            &signer,
            maintenant() - 60,
            maintenant() + 3600,
        ));
        h.dns_reponse = rep.to_vec().unwrap();
        classer(valider(h, question(&victime), ancre))
    }

    /// Point 4c : une chaîne archivée, rejouée après l'expiration de sa signature.
    #[test]
    fn signature_perimee_refusee() {
        let verdict = verdict_signature_perimee();
        assert_eq!(verdict, "reject", "signature périmée acceptée");
    }

    fn verdict_signature_perimee() -> &'static str {
        let (mut h, ancre, signer) = fixture_complete();
        let enr = a(&h.zone, 1);
        let mut rep = question(&h.zone);
        rep.add_answer(enr.clone());
        rep.add_answer(record_signe_par(
            &h.zone,
            &h.zone,
            vec![enr],
            &signer,
            maintenant() - 20_000,
            maintenant() - 10_000,
        ));
        h.dns_reponse = rep.to_vec().unwrap();
        classer(valider(h.clone(), question(&h.zone), ancre))
    }

    fn verdict_zone_signee_valide() -> &'static str {
        let (h, ancre, _) = fixture_complete();
        classer(valider(h.clone(), question(&h.zone), ancre))
    }

    /// Zone signée mais réponse sans RRSIG sur l'adresse : rien à valider.
    fn verdict_signature_absente() -> &'static str {
        let (mut h, ancre, _) = fixture_complete();
        let nom = h.zone.clone();
        let mut rep = question(&nom);
        rep.add_answer(a(&nom, 1));
        h.dns_reponse = rep.to_vec().unwrap();
        classer(valider(h, question(&nom), ancre))
    }

    /// Zone non signée prouvée par NSEC, sur le chemin complet : le validateur
    /// échoue sur la réponse sans RRSIG, la preuve d'absence de DS vient du
    /// parent, la réponse est servie. Une réponse non signée ne peut être
    /// acceptée que par ce chemin : `Ok` vaut donc « accept_unsigned ».
    fn verdict_zone_non_signee_nsec() -> &'static str {
        let (h, ancre, enfant) = parent_fixture(true, false, false);
        if valider(h, question(&enfant), ancre).is_ok() {
            "accept_unsigned"
        } else {
            "reject"
        }
    }

    /// Même cas avec une preuve NSEC3 opt-out : hickory 0.24 ne valide aucune
    /// négation NSEC3, la preuve n'arrive jamais et le chemin complet refuse.
    fn verdict_zone_non_signee_nsec3() -> &'static str {
        let (h, ancre, enfant) = parent_fixture(true, false, true);
        if valider(h, question(&enfant), ancre).is_ok() {
            "accept_unsigned"
        } else {
            "reject"
        }
    }

    /// Le cas légitime reste accepté, ET c'est bien le message validé qui ressort.
    #[test]
    fn reponse_legitime_rendue_depuis_le_message_valide() {
        let (h, ancre, _) = fixture_complete();
        let rendu = valider(h.clone(), question(&h.zone), ancre).expect("réponse légitime refusée");
        let m = Message::from_vec(&rendu).unwrap();
        assert!(m.answers().iter().any(|r| r.record_type() == RecordType::A));
    }

    /// Cas de conformité communs (mission 28, point 4) : les noms viennent de
    /// `testvectors/dnssec_vectors.json`, le verdict Windows doit être celui
    /// déclaré. Un cas déclaré applicable sans fixture échoue, et inversement.
    #[test]
    fn vecteurs_communs() {
        let texte = include_str!("../../testvectors/dnssec_vectors.json");
        let mut cas: Vec<(String, String)> = Vec::new();
        let mut courant: Option<String> = None;
        for ligne in texte.lines() {
            let ligne = ligne.trim();
            if let Some(reste) = ligne.strip_prefix("\"name\": \"") {
                if let Some(fin) = reste.find('"') {
                    courant = Some(reste[..fin].to_string());
                }
            }
            // Les plateformes peuvent être sur une ligne à elles ou groupées :
            // on cherche la clé n'importe où dans la ligne.
            if let Some(idebut) = ligne.find("\"windows\": \"") {
                let reste = &ligne[idebut + "\"windows\": \"".len()..];
                if let Some(fin) = reste.find('"') {
                    if let Some(nom) = &courant {
                        cas.push((nom.clone(), reste[..fin].to_string()));
                    }
                }
            }
        }
        assert!(!cas.is_empty(), "aucun cas lu dans le fichier commun");

        let fixtures: Vec<(&str, fn() -> &'static str)> = vec![
            ("signed_zone_valid", verdict_zone_signee_valide),
            (
                "unsigned_zone_nsec_proves_no_ds",
                verdict_zone_non_signee_nsec,
            ),
            ("unsigned_zone_nsec3_opt_out", verdict_zone_non_signee_nsec3),
            ("forged_address_in_signed_zone", verdict_adresse_forgee),
            (
                "missing_signature_on_signed_zone",
                verdict_signature_absente,
            ),
            ("expired_signature", verdict_signature_perimee),
            ("signature_by_wrong_zone", verdict_autre_zone),
            ("nxdomain_with_nsec_proof", verdict_nxdomain_nsec),
            ("nodata_with_nsec_proof", verdict_nodata_nsec),
        ];

        for (nom, attendu) in &cas {
            let fixture = fixtures.iter().find(|(n, _)| n == nom);
            match (attendu.as_str(), fixture) {
                ("n/a", Some(_)) => {
                    panic!("cas {nom} : non applicable à Windows mais une fixture existe")
                }
                ("n/a", None) => {}
                (_, None) => panic!("cas {nom} : déclaré applicable à Windows sans fixture"),
                (_, Some((_, f))) => assert_eq!(
                    f(),
                    attendu.as_str(),
                    "cas {nom} : verdict Windows inattendu"
                ),
            }
        }
        for (nom, _) in &fixtures {
            assert!(
                cas.iter().any(|(n, _)| n == nom),
                "fixture {nom} sans cas correspondant dans le fichier commun"
            );
        }
    }

    // ---- Mission 28, point 2 : une zone non signée n'est acceptée QUE si la
    // réponse retenue par le validateur contient une preuve d'absence de DS
    // couvrant le nom demandé.

    fn nsec_rr(proprietaire: &str, suivant: &str, types: &[RecordType]) -> Record {
        Record::from_rdata(
            Name::parse(proprietaire, None).unwrap(),
            300,
            RData::DNSSEC(DNSSECRData::NSEC(
                hickory_proto::rr::dnssec::rdata::NSEC::new(
                    Name::parse(suivant, None).unwrap(),
                    types.to_vec(),
                ),
            )),
        )
    }

    fn nsec3_rr(zone: &str, nom: &Name, opt_out: bool, annoncer_ds: bool) -> Record {
        use hickory_proto::rr::dnssec::Nsec3HashAlgorithm;
        let sel: Vec<u8> = vec![0xAB, 0xCD];
        let empreinte = Nsec3HashAlgorithm::SHA1.hash(&sel, nom, 0).unwrap();
        let hache = base32hex(empreinte.as_ref());
        let mut types = vec![RecordType::NS, RecordType::SOA];
        if annoncer_ds {
            types.push(RecordType::DS);
        }
        Record::from_rdata(
            Name::parse(&format!("{hache}.{zone}"), None).unwrap(),
            300,
            RData::DNSSEC(DNSSECRData::NSEC3(
                hickory_proto::rr::dnssec::rdata::NSEC3::new(
                    Nsec3HashAlgorithm::SHA1,
                    opt_out,
                    0,
                    sel,
                    empreinte.as_ref().to_vec(),
                    types,
                ),
            )),
        )
    }

    fn message_autorite(rr: Record) -> Message {
        let mut m = Message::new();
        m.add_query(hickory_proto::op::Query::query(
            Name::parse("unsigned.example.test.", None).unwrap(),
            RecordType::A,
        ));
        m.add_name_server(rr);
        m
    }

    fn question_non_signee() -> hickory_proto::op::Query {
        hickory_proto::op::Query::query(
            Name::parse("unsigned.example.test.", None).unwrap(),
            RecordType::A,
        )
    }

    /// Message négatif signé : SOA et NSEC de la zone, chacun avec son RRSIG.
    fn message_negatif(
        nom: &Name,
        rcode: ResponseCode,
        nsec: Record,
        zone: &Name,
        signer: &SigSigner,
    ) -> Message {
        let soa = Record::from_rdata(
            zone.clone(),
            300,
            RData::SOA(SOA::new(
                Name::parse("ns.example.test.", None).unwrap(),
                Name::parse("hostmaster.example.test.", None).unwrap(),
                1,
                3600,
                600,
                86400,
                300,
            )),
        );
        let mut m = Message::new();
        m.set_response_code(rcode);
        m.add_query(Query::query(nom.clone(), RecordType::A));
        m.add_name_server(soa.clone());
        m.add_name_server(record_signe(zone, vec![soa], signer));
        let nom_nsec = nsec.name().clone();
        m.add_name_server(nsec.clone());
        m.add_name_server(record_signe(&nom_nsec, vec![nsec], signer));
        m
    }

    /// NXDOMAIN prouvé par NSEC : nom absent et wildcard absent.
    fn verdict_nxdomain_nsec() -> &'static str {
        let (mut h, ancre, signer) = fixture_complete();
        let absent = Name::parse("absent.example.test.", None).unwrap();
        let nsec = nsec_rr(
            "example.test.",
            "zzz.example.test.",
            &[RecordType::NS, RecordType::SOA],
        );
        h.dns_reponse = message_negatif(&absent, ResponseCode::NXDomain, nsec, &h.zone, &signer)
            .to_vec()
            .unwrap();
        classer(valider(h, question(&absent), ancre))
    }

    /// NODATA prouvé par NSEC : le nom existe, le bitmap n'annonce pas A.
    fn verdict_nodata_nsec() -> &'static str {
        let (mut h, ancre, signer) = fixture_complete();
        let present = Name::parse("www.example.test.", None).unwrap();
        let nsec = nsec_rr(
            "www.example.test.",
            "zzz.example.test.",
            &[RecordType::NS, RecordType::SOA, RecordType::TXT],
        );
        h.dns_reponse = message_negatif(&present, ResponseCode::NoError, nsec, &h.zone, &signer)
            .to_vec()
            .unwrap();
        classer(valider(h, question(&present), ancre))
    }

    #[test]
    fn nxdomain_sans_preuve_refuse() {
        let (mut h, ancre, signer) = fixture_complete();
        let absent = Name::parse("absent.example.test.", None).unwrap();
        // SOA seule : hickory ne peut pas prouver l'inexistence.
        let mut m = message_negatif(
            &absent,
            ResponseCode::NXDomain,
            nsec_rr("example.test.", "zzz.example.test.", &[RecordType::NS]),
            &h.zone,
            &signer,
        );
        m.name_servers_mut()
            .retain(|r| r.record_type() != RecordType::NSEC);
        h.dns_reponse = m.to_vec().unwrap();
        assert_eq!(classer(valider(h, question(&absent), ancre)), "reject");
    }

    #[test]
    fn nodata_sans_nsec_au_nom_demande_refuse() {
        let (mut h, ancre, signer) = fixture_complete();
        let present = Name::parse("www.example.test.", None).unwrap();
        // NSEC d'un autre nom : il ne prouve pas l'absence de A à ce nom.
        let nsec = nsec_rr(
            "autre.example.test.",
            "zzz.example.test.",
            &[RecordType::NS, RecordType::SOA],
        );
        h.dns_reponse = message_negatif(&present, ResponseCode::NoError, nsec, &h.zone, &signer)
            .to_vec()
            .unwrap();
        assert_eq!(classer(valider(h, question(&present), ancre)), "reject");
    }

    /// Limite connue (`docs/securite/problemes-connus.md`) : hickory 0.24 ne
    /// valide que les négations NSEC, et `nxdomain_prouve`/`nodata_prouve`
    /// n'acceptent qu'un NSEC. Un NXDOMAIN dont la seule preuve est un NSEC3
    /// signé reste donc refusé : le client renvoie SERVFAIL au lieu du nom
    /// inexistant, jamais une réponse acceptée sans preuve vérifiée. Ce test
    /// fige la limite : le jour où la validation acceptera NSEC3, il échouera
    /// et il faudra la lever dans les deux fonctions et dans les docs.
    #[test]
    fn nxdomain_nsec3_seul_refuse() {
        let (mut h, ancre, signer) = fixture_complete();
        let absent = Name::parse("absent.example.test.", None).unwrap();
        let nsec3 = nsec3_rr("example.test.", &absent, false, false);
        h.dns_reponse = message_negatif(&absent, ResponseCode::NXDomain, nsec3, &h.zone, &signer)
            .to_vec()
            .unwrap();
        assert_eq!(classer(valider(h, question(&absent), ancre)), "reject");
    }

    /// Les signatures d'une réponse négative passent aussi par le contrôle
    /// d'horloge : une preuve archivée et rejouée est refusée.
    #[test]
    fn negatif_a_signature_perimee_refuse() {
        let (mut h, ancre, signer) = fixture_complete();
        let absent = Name::parse("absent.example.test.", None).unwrap();
        let nsec = nsec_rr(
            "example.test.",
            "zzz.example.test.",
            &[RecordType::NS, RecordType::SOA],
        );
        let mut m = Message::new();
        m.set_response_code(ResponseCode::NXDomain);
        m.add_query(Query::query(absent.clone(), RecordType::A));
        let soa = Record::from_rdata(
            h.zone.clone(),
            300,
            RData::SOA(SOA::new(
                Name::parse("ns.example.test.", None).unwrap(),
                Name::parse("hostmaster.example.test.", None).unwrap(),
                1,
                3600,
                600,
                86400,
                300,
            )),
        );
        m.add_name_server(soa.clone());
        m.add_name_server(record_signe_par(
            &h.zone,
            &h.zone,
            vec![soa],
            &signer,
            maintenant() - 20_000,
            maintenant() - 10_000,
        ));
        let nom_nsec = nsec.name().clone();
        m.add_name_server(nsec.clone());
        m.add_name_server(record_signe_par(
            &nom_nsec,
            &h.zone,
            vec![nsec],
            &signer,
            maintenant() - 20_000,
            maintenant() - 10_000,
        ));
        h.dns_reponse = m.to_vec().unwrap();
        assert_eq!(classer(valider(h, question(&absent), ancre)), "reject");
    }

    #[test]
    fn zone_non_signee_prouvee_par_nsec_acceptee() {
        let m = message_autorite(nsec_rr(
            "example.test.",
            "zzz.example.test.",
            &[RecordType::NS, RecordType::SOA],
        ));
        assert_eq!(
            est_zone_non_signee(&question_non_signee(), &m, &m),
            Ok(true)
        );
        assert_eq!(
            controler(&question_non_signee(), &m, &m, maintenant() as i64),
            Ok(())
        );
    }

    #[test]
    fn nsec_annoncant_ds_refuse() {
        let m = message_autorite(nsec_rr(
            "example.test.",
            "zzz.example.test.",
            &[RecordType::NS, RecordType::SOA, RecordType::DS],
        ));
        assert_eq!(
            est_zone_non_signee(&question_non_signee(), &m, &m),
            Ok(false)
        );
        assert!(controler(&question_non_signee(), &m, &m, maintenant() as i64).is_err());
    }

    #[test]
    fn nsec_hors_intervalle_refuse() {
        // L'enregistrement ne couvre pas le nom demandé : aucune preuve.
        let m = message_autorite(nsec_rr(
            "aaa.example.test.",
            "bbb.example.test.",
            &[RecordType::NS, RecordType::SOA],
        ));
        assert_eq!(
            est_zone_non_signee(&question_non_signee(), &m, &m),
            Ok(false)
        );
    }

    #[test]
    fn preuve_seulement_dans_le_buffer_brut_refusee() {
        // Le validateur n'a rien retenu : le NSEC n'est que dans le buffer reçu.
        let brut = message_autorite(nsec_rr(
            "example.test.",
            "zzz.example.test.",
            &[RecordType::NS, RecordType::SOA],
        ));
        let mut valide = Message::new();
        valide.add_query(question_non_signee());
        assert_eq!(
            est_zone_non_signee(&question_non_signee(), &valide, &brut),
            Ok(false)
        );
    }

    #[test]
    fn zone_non_signee_prouvee_par_nsec3_opt_out_acceptee() {
        let nom = Name::parse("unsigned.example.test.", None).unwrap();
        let m = message_autorite(nsec3_rr("example.test.", &nom, true, false));
        assert_eq!(
            est_zone_non_signee(&question_non_signee(), &m, &m),
            Ok(true)
        );
        assert_eq!(
            controler(&question_non_signee(), &m, &m, maintenant() as i64),
            Ok(())
        );
    }

    #[test]
    fn nsec3_sans_opt_out_refuse() {
        let nom = Name::parse("unsigned.example.test.", None).unwrap();
        let m = message_autorite(nsec3_rr("example.test.", &nom, false, false));
        assert_eq!(
            est_zone_non_signee(&question_non_signee(), &m, &m),
            Ok(false)
        );
    }

    #[test]
    fn nsec3_annoncant_ds_refuse() {
        let nom = Name::parse("unsigned.example.test.", None).unwrap();
        let m = message_autorite(nsec3_rr("example.test.", &nom, true, true));
        assert_eq!(
            est_zone_non_signee(&question_non_signee(), &m, &m),
            Ok(false)
        );
    }

    // ---- Zone non signée de bout en bout : le validateur échoue sur une
    // réponse sans RRSIG, la preuve d'absence de DS est alors demandée au
    // parent (NSEC signé, bitmap NS sans DS), puis la réponse reçue est servie
    // dans la limite de la zone prouvée.

    /// Parent signé (`example.test.`) qui délègue `unsigned.example.test.` et
    /// répond à la question A de l'enfant SANS signature.
    #[derive(Clone)]
    struct HandleParent {
        dnskey: Vec<u8>,
        ds: Vec<u8>,
        a: Vec<u8>,
        /// CNAME signé de `alias.example.test.` vers `unsigned.example.test.`,
        /// suivi de l'adresse NON signée de la cible.
        alias: Vec<u8>,
    }

    impl DnsHandle for HandleParent {
        type Response = Pin<Box<dyn Stream<Item = Result<DnsResponse, ProtoError>> + Send + Unpin>>;
        type Error = ProtoError;

        fn send<R: Into<DnsRequest> + Unpin + Send + 'static>(&self, request: R) -> Self::Response {
            let q = request.into();
            let question = q.queries().first().cloned().unwrap();
            let alias = Name::parse("alias.example.test.", None).unwrap();
            let brut = if question.name().eq_case(&alias) {
                self.alias.clone()
            } else {
                match question.query_type() {
                    RecordType::DNSKEY => self.dnskey.clone(),
                    RecordType::DS => self.ds.clone(),
                    RecordType::A => self.a.clone(),
                    _ => Vec::new(),
                }
            };
            let resultat = Message::from_vec(&brut)
                .map_err(ProtoError::from)
                .and_then(DnsResponse::from_message);
            Box::pin(stream::iter(vec![resultat]))
        }
    }

    /// `delegation` : le NSEC du parent annonce NS (vraie délégation) ou pas.
    /// `ds_present` : le parent sert un DS signé (zone enfant signée).
    /// `nsec3` : le parent prouve l'absence de DS par un NSEC3 opt-out.
    fn parent_fixture(
        delegation: bool,
        ds_present: bool,
        nsec3: bool,
    ) -> (HandleParent, TrustAnchor, Name) {
        let zone = Name::parse("example.test.", None).unwrap();
        let enfant = Name::parse("unsigned.example.test.", None).unwrap();
        let rng = ring::rand::SystemRandom::new();
        let graine = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let privee = ring::signature::Ed25519KeyPair::from_pkcs8(graine.as_ref()).unwrap();
        let cle = KeyPair::from_ed25519(privee);
        let signer = SigSigner::dnssec(
            cle.to_dnskey(Algorithm::ED25519).unwrap(),
            cle,
            zone.clone(),
            std::time::Duration::from_secs(3600),
        );
        let dnskey = signer.to_dnskey().unwrap();
        let dnskey_rr = Record::from_rdata(
            zone.clone(),
            3600,
            RData::DNSSEC(DNSSECRData::DNSKEY(dnskey.clone())),
        );
        let mut m_dnskey = Message::new();
        m_dnskey.add_query(Query::query(zone.clone(), RecordType::DNSKEY));
        m_dnskey.add_answer(dnskey_rr.clone());
        m_dnskey.add_answer(record_signe(&zone, vec![dnskey_rr], &signer));

        let soa = Record::from_rdata(
            zone.clone(),
            300,
            RData::SOA(SOA::new(
                Name::parse("ns.example.test.", None).unwrap(),
                Name::parse("hostmaster.example.test.", None).unwrap(),
                1,
                3600,
                600,
                86400,
                300,
            )),
        );
        let mut m_ds = Message::new();
        m_ds.set_response_code(ResponseCode::NoError);
        m_ds.add_query(Query::query(enfant.clone(), RecordType::DS));
        m_ds.add_name_server(soa.clone());
        m_ds.add_name_server(record_signe_par(
            &zone,
            &zone,
            vec![soa],
            &signer,
            maintenant() - 60,
            maintenant() + 3600,
        ));
        if ds_present {
            let ds_rr = Record::from_rdata(
                enfant.clone(),
                300,
                RData::DNSSEC(DNSSECRData::DS(hickory_proto::rr::dnssec::rdata::DS::new(
                    12345,
                    Algorithm::ED25519,
                    hickory_proto::rr::dnssec::DigestType::SHA256,
                    vec![0xAA; 32],
                ))),
            );
            m_ds.add_answer(ds_rr.clone());
            m_ds.add_answer(record_signe_par(
                &enfant,
                &zone,
                vec![ds_rr],
                &signer,
                maintenant() - 60,
                maintenant() + 3600,
            ));
        } else if nsec3 {
            let preuve = nsec3_rr("example.test.", &enfant, true, false);
            let nom_preuve = preuve.name().clone();
            m_ds.add_name_server(preuve.clone());
            m_ds.add_name_server(record_signe_par(
                &nom_preuve,
                &zone,
                vec![preuve],
                &signer,
                maintenant() - 60,
                maintenant() + 3600,
            ));
        } else {
            let types: Vec<RecordType> = if delegation {
                vec![RecordType::NS]
            } else {
                vec![RecordType::A]
            };
            let nsec = nsec_rr("unsigned.example.test.", "zzz.example.test.", &types);
            m_ds.add_name_server(nsec.clone());
            m_ds.add_name_server(record_signe_par(
                &enfant,
                &zone,
                vec![nsec],
                &signer,
                maintenant() - 60,
                maintenant() + 3600,
            ));
        }

        let a = Record::from_rdata(
            enfant.clone(),
            60,
            RData::A(hickory_proto::rr::rdata::A::new(192, 0, 2, 7)),
        );
        let mut m_a = Message::new();
        m_a.add_query(Query::query(enfant.clone(), RecordType::A));
        m_a.add_answer(a.clone());

        // Réponse d'une zone SIGNÉE : un CNAME signé vers la zone non signée,
        // accompagné de l'adresse non signée de la cible (ce que fait un
        // résolveur récursif).
        let alias = Name::parse("alias.example.test.", None).unwrap();
        let cname = Record::from_rdata(
            alias.clone(),
            60,
            RData::CNAME(hickory_proto::rr::rdata::CNAME(enfant.clone())),
        );
        let mut m_alias = Message::new();
        m_alias.add_query(Query::query(alias.clone(), RecordType::A));
        m_alias.add_answer(cname.clone());
        m_alias.add_answer(record_signe_par(
            &alias,
            &zone,
            vec![cname],
            &signer,
            maintenant() - 60,
            maintenant() + 3600,
        ));
        m_alias.add_answer(a);

        let publique =
            PublicKeyEnum::from_public_bytes(dnskey.public_key(), Algorithm::ED25519).unwrap();
        let mut ancre = TrustAnchor::new();
        ancre.insert_trust_anchor(&publique);
        (
            HandleParent {
                dnskey: m_dnskey.to_vec().unwrap(),
                ds: m_ds.to_vec().unwrap(),
                a: m_a.to_vec().unwrap(),
                alias: m_alias.to_vec().unwrap(),
            },
            ancre,
            enfant,
        )
    }

    #[test]
    fn zone_non_signee_prouvee_acceptee_de_bout_en_bout() {
        let (h, ancre, enfant) = parent_fixture(true, false, false);
        let sortie = valider(h, question(&enfant), ancre).expect("zone non signée refusée");
        let m = Message::from_vec(&sortie).unwrap();
        assert!(
            m.answers().iter().any(|rr| matches!(
                rr.data(),
                Some(RData::A(a)) if a.0 == std::net::Ipv4Addr::new(192, 0, 2, 7)
            )),
            "la réponse de la zone non signée n'est pas servie"
        );
    }

    /// CNAME signé d'une zone signée vers une zone non signée : hickory retire
    /// du message validé l'adresse de la cible (aucune signature à vérifier).
    /// Elle revient sur preuve d'absence de DS, et la réponse porte alors le
    /// CNAME ET l'adresse ; sans le correctif, seul le CNAME était rendu.
    #[test]
    fn cname_vers_zone_non_signee_complete_la_reponse() {
        let (h, ancre, enfant) = parent_fixture(true, false, false);
        let alias = Name::parse("alias.example.test.", None).unwrap();
        let sortie =
            valider(h, question(&alias), ancre).expect("CNAME vers zone non signée refusé");
        let m = Message::from_vec(&sortie).unwrap();
        assert!(
            m.answers().iter().any(|rr| matches!(
                rr.data(),
                Some(RData::CNAME(c)) if c.0 == enfant
            )),
            "le CNAME validé n'est pas rendu"
        );
        assert!(
            m.answers().iter().any(|rr| matches!(
                rr.data(),
                Some(RData::A(a)) if a.0 == std::net::Ipv4Addr::new(192, 0, 2, 7)
            )),
            "l'adresse de la cible non signée n'est pas servie"
        );
    }

    /// Même chaîne, mais le parent sert un DS pour la cible : elle est signée,
    /// donc l'adresse non signée est une forgerie et la réponse est refusée.
    #[test]
    fn cname_vers_zone_signee_refuse() {
        let (h, ancre, _) = parent_fixture(true, true, false);
        let alias = Name::parse("alias.example.test.", None).unwrap();
        assert_eq!(classer(valider(h, question(&alias), ancre)), "reject");
    }

    #[test]
    fn zone_signee_reponse_non_signee_refusee() {
        // Le parent sert un DS signé : la zone enfant est signée, une réponse
        // non signée est une forgerie.
        let (h, ancre, enfant) = parent_fixture(true, true, false);
        assert_eq!(classer(valider(h, question(&enfant), ancre)), "reject");
    }

    #[test]
    fn refus_sans_preuve_de_delegation_conserve() {
        // NSEC d'un nom ordinaire (bitmap sans NS) : rien ne prouve une zone
        // non signée, le refus du validateur est conservé.
        let (h, ancre, enfant) = parent_fixture(false, false, false);
        assert_eq!(classer(valider(h, question(&enfant), ancre)), "reject");
    }

    /// Une zone non signée sous un parent NSEC3 reste refusée de bout en bout :
    /// hickory 0.24 ne valide aucune négation NSEC3, donc la preuve d'absence de
    /// DS n'arrive jamais. `est_zone_non_signee` saurait la lire (test
    /// ci-dessus) ; le chemin complet échoue fermé. Ce test fige la limite :
    /// le jour où hickory validera NSEC3, il faudra le retourner et lever la
    /// limite dans les docs.
    #[test]
    fn zone_non_signee_sous_parent_nsec3_refusee() {
        let (h, ancre, enfant) = parent_fixture(true, false, true);
        assert_eq!(classer(valider(h, question(&enfant), ancre)), "reject");
    }

    #[test]
    fn reponse_signee_acceptee_et_alteration_refusee() {
        let (mut h, ancre) = fixture();
        assert_eq!(h.zone.to_ascii(), "example.test.");
        assert_eq!(h.dnskey.algorithm(), Algorithm::ED25519);
        let q = Message::from_vec(&h.dns_reponse).unwrap();
        valider(h.clone(), q, ancre.clone()).expect("réponse signée refusée");

        h.alterer = true;
        let q = Message::from_vec(&h.dns_reponse).unwrap();
        assert!(valider(h, q, ancre).is_err(), "adresse altérée acceptée");
    }
}

#[cfg(test)]
mod tests_ancres {
    use super::*;
    use hickory_proto::rr::dnssec::rdata::DNSKEY;

    /// KSK-2024 est bien livrée, et son empreinte est celle publiée par l'IANA.
    #[test]
    fn ksk_2024_livree_et_conforme_a_l_iana() {
        let cle = PublicKeyEnum::from_public_bytes(KSK_2024, Algorithm::RSASHA256)
            .expect("clé KSK-2024 illisible");
        assert!(ancres_racine().contains(&cle));
        let dnskey = DNSKEY::new(true, true, false, Algorithm::RSASHA256, KSK_2024.to_vec());
        let racine = hickory_proto::rr::Name::root();
        assert_eq!(dnskey.calculate_key_tag().unwrap(), 38696);
        let empreinte = dnskey
            .to_digest(&racine, hickory_proto::rr::dnssec::DigestType::SHA256)
            .unwrap();
        let hex: String = empreinte
            .as_ref()
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect();
        assert_eq!(
            hex,
            "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16"
        );
    }

    /// Pendant un roulement, plusieurs ancres coexistent : la KSK-2024 livrée
    /// par ce dépôt et les ancres de hickory (dont KSK-2017, 20326). Une seule
    /// ancre livrée casserait soit aujourd'hui, soit au retrait de l'ancienne.
    #[test]
    fn les_ancres_du_roulement_coexistent() {
        let ancre = ancres_racine();
        let cle_2024 = PublicKeyEnum::from_public_bytes(KSK_2024, Algorithm::RSASHA256)
            .expect("clé KSK-2024 illisible");
        assert!(
            ancre.contains(&cle_2024),
            "KSK-2024 absente des ancres livrées"
        );
        assert!(
            ancre.len() >= 2,
            "une seule ancre livrée : un roulement la rendrait caduque"
        );
        // Toute ancre par défaut de hickory doit survivre : `ancres_racine`
        // ajoute, elle ne remplace pas.
        let defaut = TrustAnchor::default();
        assert!(defaut.len() >= 2);
        for i in 0..defaut.len() {
            assert!(
                ancre.contains_dnskey_bytes(defaut.get(i)),
                "ancre par défaut {i} perdue par les ancres livrées"
            );
        }
    }
}
