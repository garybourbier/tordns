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
use hickory_proto::rr::dnssec::TrustAnchor;
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

/// Valide `requete` et retourne la réponse authentifiée, ré-encodée. Une zone
/// non signée est acceptée par hickory (délégation non signée), comme sur
/// Internet ; seule une signature fausse ou une chaîne rompue est refusée.
pub fn resoudre(doh: &ClientDoh, requete: &[u8]) -> Result<Vec<u8>, String> {
    let message = Message::from_vec(requete).map_err(|e| e.to_string())?;
    valider(
        DoHHandle {
            doh: Arc::new(doh.clone()),
        },
        message,
        TrustAnchor::default(),
    )
}

fn valider<H>(handle: H, message: Message, ancre: TrustAnchor) -> Result<Vec<u8>, String>
where
    H: DnsHandle<Error = ProtoError> + 'static,
{
    let nœud = DnssecDnsHandle::with_trust_anchor(handle, ancre);
    let mut flux = nœud.send(DnsRequest::from(message));
    let reponse = futures::executor::block_on(futures::StreamExt::next(&mut flux))
        .ok_or_else(|| "validation DNSSEC sans réponse".to_string())?
        .map_err(|e| format!("validation DNSSEC : {e}"))?;
    Ok(reponse.into_buffer())
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
        let rrsig = RRSIG::new(
            rrset[0].record_type(),
            Algorithm::ED25519,
            nom.num_labels(),
            rrset[0].ttl(),
            maintenant() + 3600,
            maintenant() - 60,
            signer.calculate_key_tag().unwrap(),
            nom.clone(),
            vec![],
        );
        let sig: Record<RRSIG> =
            Record::from_rdata(nom.clone(), rrset[0].ttl(), rrsig.clone());
        let tbs = tbs::rrset_tbs_with_rrsig(&sig, &rrset).unwrap();
        let octets = signer.sign(&tbs).unwrap();
        let signee = RRSIG::new(
            rrset[0].record_type(),
            Algorithm::ED25519,
            nom.num_labels(),
            rrset[0].ttl(),
            maintenant() + 3600,
            maintenant() - 60,
            signer.calculate_key_tag().unwrap(),
            nom.clone(),
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
        type Response =
            Pin<Box<dyn Stream<Item = Result<DnsResponse, ProtoError>> + Send + Unpin>>;
        type Error = ProtoError;

        fn send<R: Into<DnsRequest> + Unpin + Send + 'static>(
            &self,
            request: R,
        ) -> Self::Response {
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
        reponse.add_query(hickory_proto::op::Query::query(
            zone.clone(),
            RecordType::A,
        ));
        reponse.add_answer(a.clone());
        reponse.add_answer(record_signe(&zone, vec![a], &signer));

        let publique = PublicKeyEnum::from_public_bytes(
            dnskey.public_key(),
            Algorithm::ED25519,
        )
        .unwrap();
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
        )
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
