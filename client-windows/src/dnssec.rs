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
use hickory_proto::rr::{Name, RData, RecordType};
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
    H: DnsHandle<Error = ProtoError> + 'static,
{
    let question = message
        .queries()
        .first()
        .cloned()
        .ok_or_else(|| "requête sans question".to_string())?;
    let nœud = DnssecDnsHandle::with_trust_anchor(handle, ancre);
    let mut flux = nœud.send(DnsRequest::from(message));
    let reponse = futures::executor::block_on(futures::StreamExt::next(&mut flux))
        .ok_or_else(|| "validation DNSSEC sans réponse".to_string())?
        .map_err(|e| format!("validation DNSSEC : {e}"))?;
    // Le message brut, tel que le nœud l'a envoyé : on y lit les RRSIG pour les
    // contrôles que la bibliothèque ne fait pas (voir `controler`).
    let brut = Message::from_vec(reponse.as_buffer()).map_err(|e| e.to_string())?;
    // LE MESSAGE VALIDÉ, JAMAIS LE BUFFER. hickory retire du message les RRset qui
    // n'ont pas vérifié mais garde le buffer d'origine intact : `into_buffer()`
    // relayait donc la réponse du nœud sans filtrage (relecture du 24/11, point 4a).
    let valide = reponse.into_message();
    controler(&question, &valide, &brut, maintenant_unix())?;
    valide.to_vec().map_err(|e| e.to_string())
}

/// Vérifie si la réponse correspond à une zone non signée (délégation sans DS prouvée
/// par NSEC/NSEC3). Retourne `Ok(true)` si la zone est prouvée non signée.
fn est_zone_non_signee(
    question: &hickory_proto::op::Query,
    valide: &Message,
    brut: &Message,
) -> Result<bool, String> {
    use hickory_proto::rr::RecordType;

    let nom_question = question.name();

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
        if !repond {
            return Err("réponse validée vide pour la question posée".into());
        }
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
    use hickory_proto::rr::dnssec::rdata::{DNSSECRData, DNSKEY, RRSIG};
    use hickory_proto::rr::dnssec::{tbs, Algorithm, KeyPair, PublicKeyEnum, SigSigner};
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

    fn verdict_zone_non_signee_nsec() -> &'static str {
        let m = message_autorite(nsec_rr(
            "example.test.",
            "zzz.example.test.",
            &[RecordType::NS, RecordType::SOA],
        ));
        match est_zone_non_signee(&question_non_signee(), &m, &m) {
            Ok(true) => "accept_unsigned",
            _ => "reject",
        }
    }

    fn verdict_zone_non_signee_nsec3() -> &'static str {
        let nom = Name::parse("unsigned.example.test.", None).unwrap();
        let m = message_autorite(nsec3_rr("example.test.", &nom, true, false));
        match est_zone_non_signee(&question_non_signee(), &m, &m) {
            Ok(true) => "accept_unsigned",
            _ => "reject",
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
}
