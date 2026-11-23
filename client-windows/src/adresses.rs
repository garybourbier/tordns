//! Liste d'adresses signée (mission 12).
//!
//! Le service ne code plus l'adresse en dur : il lit le dernier manifeste
//! vérifié, déposé par la mise à jour signée, et choisit le cœur ou la
//! communauté selon `mode_adresse`. Une liste absente, expirée ou mal signée
//! fait retomber sur l'adresse saisie par l'utilisateur dans `client.conf`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::config::Config;

/// Dossier où la mise à jour dépose le manifeste vérifié.
pub fn dossier_defaut() -> PathBuf {
    std::env::var_os("PROGRAMDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("TorDNS")
        .join("maj")
}

/// Lit et vérifie `manifeste.json` + sa signature. Retourne les adresses et la
/// clé d'état (rotation), ou `None` si le cache est absent/invalide.
fn lire(dossier: &Path, cle: &str) -> Option<(BTreeMap<String, String>, String)> {
    let brut = std::fs::read(dossier.join("manifeste.json")).ok()?;
    let sig = std::fs::read(dossier.join("manifeste.json.sig")).ok()?;
    // La clé courante peut avoir été remplacée par une rotation déjà vérifiée.
    let etat: Option<crate::maj::EtatCle> = std::fs::read(dossier.join("maj.json"))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok());
    let cle = etat
        .as_ref()
        .map(|e| e.cle.as_str())
        .filter(|c| !c.is_empty())
        .unwrap_or(cle);
    let m = tordns_manifeste::verifier(&brut, &sig, cle, tordns_manifeste::maintenant()).ok()?;
    Some((m.adresses, m.cle_suivante))
}

/// Adresse effective : liste vérifiée selon le mode, sinon secours configuré.
pub fn choisir(dossier: &Path, c: &Config, cle: &str) -> String {
    if let Some((adresses, _)) = lire(dossier, cle) {
        if let Some(a) = tordns_manifeste::choisir_adresse(&c.mode_adresse, &adresses, None) {
            return a.to_string();
        }
    }
    c.onion.clone()
}

/// Variante pour le service : utilise le dossier standard et la clé épinglée.
pub fn adresse_effective(c: &Config) -> String {
    let cle = std::env::var("TORDNS_MAJ_CLE")
        .unwrap_or_else(|_| tordns_manifeste::CLE_PUBLIQUE_EPINGLEE.into());
    choisir(&dossier_defaut(), c, &cle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn ecrire(dossier: &Path, adresses: &str, expire: &str, cle: &SigningKey) -> String {
        std::fs::create_dir_all(dossier).unwrap();
        let json = format!(
            r#"{{"version":2,"expire":"{expire}","cibles":{{"client-windows":{{"url":"http://exemple.onion/x","taille":1,"sha256":"{}"}}}},"adresses":{adresses}}}"#,
            "a".repeat(64)
        );
        std::fs::write(dossier.join("manifeste.json"), &json).unwrap();
        std::fs::write(
            dossier.join("manifeste.json.sig"),
            cle.sign(json.as_bytes()).to_bytes(),
        )
        .unwrap();
        hex::encode(cle.verifying_key().to_bytes())
    }

    fn config(onion: &str, mode: &str) -> Config {
        let mut c = Config::default();
        c.onion = onion.into();
        c.mode_adresse = mode.into();
        c
    }

    #[test]
    fn choisit_le_coeur_puis_la_communaute() {
        let dossier = std::env::temp_dir().join(format!("tordns-addr-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dossier);
        let cle = SigningKey::from_bytes(&[4u8; 32]);
        let coeur = "c".repeat(56) + ".onion";
        let communaute = "m".repeat(56) + ".onion";
        let publique = ecrire(
            &dossier,
            &format!(r#"{{"coeur":"{coeur}","communaute":"{communaute}"}}"#),
            "2030-01-01T00:00:00Z",
            &cle,
        );
        assert_eq!(
            choisir(&dossier, &config("repli.onion", "coeur"), &publique),
            coeur
        );
        assert_eq!(
            choisir(&dossier, &config("repli.onion", "communaute"), &publique),
            communaute
        );
        assert_eq!(
            choisir(&dossier, &config("repli.onion", "secours"), &publique),
            coeur
        );
    }

    #[test]
    fn liste_expiree_ou_falsifiee_retombe_sur_la_configuration() {
        let dossier = std::env::temp_dir().join(format!("tordns-addr-vide-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dossier);
        let cle = SigningKey::from_bytes(&[5u8; 32]);
        let publique = ecrire(
            &dossier,
            &format!(r#"{{"coeur":"{}.onion"}}"#, "c".repeat(56)),
            "2020-01-01T00:00:00Z",
            &cle,
        );
        assert_eq!(
            choisir(&dossier, &config("repli.onion", "coeur"), &publique),
            "repli.onion"
        );
        std::fs::write(dossier.join("manifeste.json"), b"{\"version\":3}").unwrap();
        assert_eq!(
            choisir(&dossier, &config("repli.onion", "coeur"), &publique),
            "repli.onion"
        );
    }
}
