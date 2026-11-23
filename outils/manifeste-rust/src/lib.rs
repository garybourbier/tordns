//! Vérification du manifeste signé TorDNS, partagée par Windows et Android.
//!
//! La signature Ed25519 porte sur les octets exacts du fichier JSON : aucune
//! re-sérialisation n'a lieu avant vérification. La clé privée ne quitte jamais
//! le poste de publication ; seules la clé publique et les fichiers signés
//! arrivent ici.
//!
//! Le module ne fait aucune entrée/sortie réseau : il reçoit les octets déjà
//! téléchargés, ce qui permet de le tester hors ligne et de le réutiliser dans
//! le JNI Android comme dans le service Windows.

use std::collections::BTreeMap;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;

/// Taille maximale d'un manifeste : un fichier plus gros est refusé avant
/// même d'être analysé.
pub const TAILLE_MAX_MANIFESTE: usize = 64 * 1024;

/// Clé publique de test compilée par défaut. Elle ne peut rien signer : sa
/// clé privée n'a pas été conservée. La publication remplace cette valeur via
/// une variable de compilation.
pub const CLE_PUBLIQUE_EPINGLEE: &str =
    "3b6ed1b0c0d0f7a05b1a5c3f1bb1a0b1b1b0c0d0e0f00112233445566778899a";

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Cible {
    pub url: String,
    pub taille: i64,
    pub sha256: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Manifeste {
    pub version: i64,
    pub expire: String,
    #[serde(default)]
    pub cibles: BTreeMap<String, Cible>,
    #[serde(default)]
    pub images: BTreeMap<String, String>,
    #[serde(default)]
    pub adresses: BTreeMap<String, String>,
    #[serde(default, rename = "cle_suivante")]
    pub cle_suivante: String,
}

/// Raison précise d'un refus. Le client la journalise et n'applique rien.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refus(pub String);

impl fmt::Display for Refus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Refus {}

fn refus(message: impl Into<String>) -> Refus {
    Refus(message.into())
}

/// Secondes depuis l'époque UNIX, sans dépendre de l'horloge locale.
pub fn maintenant() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Vérifie la signature puis la forme du manifeste. `maintenant_s` est injecté
/// pour rendre les tests d'expiration déterministes.
pub fn verifier(
    brut: &[u8],
    signature: &[u8],
    cle_publique_hex: &str,
    maintenant_s: i64,
) -> Result<Manifeste, Refus> {
    if brut.len() > TAILLE_MAX_MANIFESTE {
        return Err(refus("manifeste trop gros"));
    }
    let cle = hexa(cle_publique_hex).ok_or_else(|| refus("clé publique invalide"))?;
    if cle.len() != 32 {
        return Err(refus("clé publique invalide"));
    }
    let cle: [u8; 32] = cle.try_into().expect("longueur vérifiée");
    let verifying = VerifyingKey::from_bytes(&cle).map_err(|_| refus("clé publique invalide"))?;
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| refus(format!("signature de taille invalide ({})", signature.len())))?;
    verifying
        .verify_strict(brut, &Signature::from_bytes(&signature))
        .map_err(|_| refus("signature invalide"))?;

    let m: Manifeste =
        serde_json::from_slice(brut).map_err(|e| refus(format!("manifeste illisible : {e}")))?;
    if m.version < 1 {
        return Err(refus("version absente ou nulle"));
    }
    let expiration = epoch_rfc3339(&m.expire)
        .ok_or_else(|| refus(format!("date d'expiration invalide : {:?}", m.expire)))?;
    if expiration <= maintenant_s {
        return Err(refus(format!("manifeste expiré depuis {expiration}")));
    }
    if m.cibles.is_empty() {
        return Err(refus("aucune cible"));
    }
    for (nom, c) in &m.cibles {
        let url_ok = (c.url.starts_with("https://") || c.url.starts_with("http://"))
            && c.url.len() > 8
            && !c.url.chars().any(|c| c.is_whitespace() || c == '|');
        if !url_ok {
            return Err(refus(format!("cible {nom:?} : URL invalide {:?}", c.url)));
        }
        if c.taille < 1 {
            return Err(refus(format!("cible {nom:?} : taille invalide")));
        }
        if !hexa_est_sha256(&c.sha256) {
            return Err(refus(format!("cible {nom:?} : SHA-256 invalide")));
        }
    }
    for (nom, image) in &m.images {
        let (reference, empreinte) = image
            .rsplit_once("@sha256:")
            .ok_or_else(|| refus(format!("image {nom:?} : nom@sha256:… attendu")))?;
        if reference.is_empty() || !hexa_est_sha256(empreinte) {
            return Err(refus(format!("image {nom:?} : empreinte invalide")));
        }
    }
    for (nom, adresse) in &m.adresses {
        if !adresse_onion(adresse) {
            return Err(refus(format!("adresse {nom:?} invalide")));
        }
    }
    if !m.cle_suivante.is_empty() && !hexa_est_sha256(&m.cle_suivante) {
        return Err(refus("clé suivante invalide"));
    }
    Ok(m)
}

/// Vérifie et exige une version strictement supérieure : un rejeu signé d'un
/// ancien manifeste est refusé.
pub fn accepter(
    brut: &[u8],
    signature: &[u8],
    cle_publique_hex: &str,
    version_installee: i64,
    maintenant_s: i64,
) -> Result<Manifeste, Refus> {
    let m = verifier(brut, signature, cle_publique_hex, maintenant_s)?;
    if m.version <= version_installee {
        return Err(refus(format!(
            "version {} déjà installée (ou inférieure)",
            m.version
        )));
    }
    Ok(m)
}

/// Adresse à utiliser selon le réglage utilisateur. `coeur` par défaut ;
/// `secours` ne bascule sur la communauté que si le cœur manque ; `communaute`
/// force la communauté.
pub fn choisir_adresse<'a>(
    mode: &str,
    adresses: &'a BTreeMap<String, String>,
    secours_compilee: Option<&'a str>,
) -> Option<&'a str> {
    let coeur = adresses.get("coeur").map(String::as_str);
    let communaute = adresses.get("communaute").map(String::as_str);
    match mode {
        "communaute" => communaute.or(coeur).or(secours_compilee),
        "secours" => coeur.or(communaute).or(secours_compilee),
        // « cœur seulement » ne bascule jamais silencieusement sur un bénévole.
        _ => coeur.or(secours_compilee),
    }
}

/// Convertit `AAAA-MM-JJTHH:MM:SSZ` en secondes UNIX. L'outil de publication
/// écrit toujours cette forme UTC : aucun fuseau ni fraction de seconde n'est
/// accepté, ce qui évite une dépendance de calendrier dans les clients.
fn epoch_rfc3339(texte: &str) -> Option<i64> {
    let octets = texte.as_bytes();
    if octets.len() != 20
        || octets[4] != b'-'
        || octets[7] != b'-'
        || octets[10] != b'T'
        || octets[13] != b':'
        || octets[16] != b':'
        || octets[19] != b'Z'
    {
        return None;
    }
    let nombre = |debut: usize, fin: usize| -> Option<i64> {
        texte.get(debut..fin)?.parse::<i64>().ok()
    };
    let (annee, mois, jour) = (nombre(0, 4)?, nombre(5, 7)?, nombre(8, 10)?);
    let (heure, minute, seconde) = (nombre(11, 13)?, nombre(14, 16)?, nombre(17, 19)?);
    if !(1..=12).contains(&mois)
        || jour < 1
        || jour > jours_du_mois(annee, mois)
        || heure > 23
        || minute > 59
        || seconde > 60
    {
        return None;
    }
    // Algorithme civil de Hinnant : jours depuis 1970-01-01.
    let a = (14 - mois) / 12;
    let y = annee + 4800 - a;
    let m = mois + 12 * a - 3;
    let jours = jour + (153 * m + 2) / 5 + 365 * y + y / 4 - y / 100 + y / 400 - 32045
        - 2_440_588;
    Some(jours * 86_400 + heure * 3_600 + minute * 60 + seconde)
}

fn jours_du_mois(annee: i64, mois: i64) -> i64 {
    match mois {
        2 if annee % 4 == 0 && (annee % 100 != 0 || annee % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

fn hexa_est_sha256(valeur: &str) -> bool {
    valeur.len() == 64 && valeur.bytes().all(|o| o.is_ascii_hexdigit())
}

fn hexa(valeur: &str) -> Option<Vec<u8>> {
    if valeur.len() % 2 != 0 || !valeur.bytes().all(|o| o.is_ascii_hexdigit()) {
        return None;
    }
    (0..valeur.len() / 2)
        .map(|i| u8::from_str_radix(&valeur[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

fn adresse_onion(valeur: &str) -> bool {
    let Some(nom) = valeur.strip_suffix(".onion") else {
        return false;
    };
    nom.len() == 56
        && nom
            .bytes()
            .all(|o| matches!(o, b'a'..=b'z' | b'2'..=b'7'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const MAINTENANT: i64 = 1_800_000_000;

    fn signer(manifeste: &str) -> (Vec<u8>, Vec<u8>, String) {
        let graine = [7u8; 32];
        let cle = SigningKey::from_bytes(&graine);
        let brut = manifeste.as_bytes().to_vec();
        let signature = cle.sign(&brut).to_bytes().to_vec();
        (brut, signature, hexa_clé(&cle))
    }

    fn hexa_clé(cle: &SigningKey) -> String {
        cle.verifying_key()
            .to_bytes()
            .iter()
            .map(|o| format!("{o:02x}"))
            .collect()
    }

    fn manifeste(version: i64, expire: &str, adresses: &str) -> String {
        format!(
            r#"{{"version":{version},"expire":"{expire}","cibles":{{"client-windows":{{"url":"http://exemple.onion/maj/client.exe","taille":123,"sha256":"{}"}}}},"adresses":{adresses}}}"#,
            "a".repeat(64)
        )
    }

    #[test]
    fn accepte_un_manifeste_signe() {
        let (brut, sig, cle) = signer(&manifeste(2, "2030-01-01T00:00:00Z", "{}"));
        let m = accepter(&brut, &sig, &cle, 1, MAINTENANT).unwrap();
        assert_eq!(m.version, 2);
        assert_eq!(m.cibles["client-windows"].taille, 123);
    }

    #[test]
    fn refuse_signature_alteree_et_rejeu() {
        let (brut, sig, cle) = signer(&manifeste(2, "2030-01-01T00:00:00Z", "{}"));
        let mut altere = brut.clone();
        altere[10] ^= 1;
        assert!(accepter(&altere, &sig, &cle, 1, MAINTENANT).is_err());
        let mut mauvaise = sig.clone();
        mauvaise[0] ^= 1;
        assert!(accepter(&brut, &mauvaise, &cle, 1, MAINTENANT).is_err());
        assert!(accepter(&brut, &sig, &cle, 2, MAINTENANT).is_err());
    }

    #[test]
    fn refuse_expiration_et_adresse_invalide() {
        let (brut, sig, cle) = signer(&manifeste(2, "2020-01-01T00:00:00Z", "{}"));
        assert!(accepter(&brut, &sig, &cle, 1, MAINTENANT).is_err());
        let (brut, sig, cle) = signer(&manifeste(
            2,
            "2030-01-01T00:00:00Z",
            r#"{"coeur":"pas-une-adresse"}"#,
        ));
        assert!(verifier(&brut, &sig, &cle, MAINTENANT).is_err());
    }

    #[test]
    fn conversion_des_dates() {
        assert_eq!(epoch_rfc3339("2030-01-01T00:00:00Z"), Some(1_893_456_000));
        assert_eq!(epoch_rfc3339("1970-01-01T00:00:00Z"), Some(0));
        assert!(epoch_rfc3339("2030-02-30T00:00:00Z").is_none());
        assert!(epoch_rfc3339("2030-01-01").is_none());
    }

    #[test]
    fn modes_d_adresse() {
        let mut a = BTreeMap::new();
        a.insert("coeur".to_string(), "c".repeat(56) + ".onion");
        a.insert("communaute".to_string(), "m".repeat(56) + ".onion");
        assert!(choisir_adresse("coeur", &a, None).unwrap().starts_with("cccc"));
        assert!(choisir_adresse("secours", &a, None).unwrap().starts_with("cccc"));
        assert!(choisir_adresse("communaute", &a, None).unwrap().starts_with("mmmm"));
        a.remove("coeur");
        assert_eq!(choisir_adresse("coeur", &a, None), None);
        assert!(choisir_adresse("secours", &a, None).unwrap().starts_with("mmmm"));
        let vide = BTreeMap::new();
        assert_eq!(choisir_adresse("coeur", &vide, Some("repli.onion")), Some("repli.onion"));
    }
}
