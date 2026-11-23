//! Mise à jour signée du client Windows (mission 12).
//!
//! Le service télécharge `manifeste.json` et sa signature par Tor, vérifie la
//! signature et la version, puis récupère l'installateur NSIS annoncé. Le
//! SHA-256 et la taille sont contrôlés avant de lancer l'installateur en
//! silencieux. Si le service ne redémarre pas, l'installateur précédent, gardé
//! en cache, est relancé.
//!
//! Aucun nom de domaine n'est journalisé : seuls la version, les erreurs et
//! les chemins d'installation apparaissent.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::Config;
use crate::doh::ClientDoh;

const TAILLE_MAX_INSTALLATEUR: usize = 256 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct ConfigMaj {
    pub manifeste_url: String,
    pub signature_url: String,
    pub socks: String,
    pub onion: String,
    pub cible: String,
    pub installateur: PathBuf,
    pub cache: PathBuf,
    pub etat: PathBuf,
    pub manifeste_cache: PathBuf,
    pub signature_cache: PathBuf,
    pub cle: String,
    pub delai: Duration,
}

impl ConfigMaj {
    /// Construit la configuration depuis les variables d'environnement et le
    /// `client.conf` déjà chargé.
    pub fn depuis(c: &Config) -> Self {
        let base = std::env::var_os("PROGRAMDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
        let dossier = base.join("TorDNS").join("maj");
        let manifeste = std::env::var("TORDNS_MAJ_MANIFESTE").unwrap_or_default();
        let signature = std::env::var("TORDNS_MAJ_SIGNATURE")
            .unwrap_or_else(|_| format!("{manifeste}.sig"));
        Self {
            manifeste_url: manifeste,
            signature_url: signature,
            socks: c.socks.clone(),
            onion: c.onion.clone(),
            cible: "client-windows".into(),
            installateur: dossier.join("TorDNS-setup.exe"),
            cache: dossier.join("TorDNS-setup.precedent.exe"),
            etat: dossier.join("maj.json"),
            manifeste_cache: dossier.join("manifeste.json"),
            signature_cache: dossier.join("manifeste.json.sig"),
            cle: std::env::var("TORDNS_MAJ_CLE")
                .unwrap_or_else(|_| tordns_manifeste::CLE_PUBLIQUE_EPINGLEE.into()),
            delai: Duration::from_secs(120),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct Etat {
    version: i64,
    #[serde(default)]
    cle: String,
}

/// Vue minimale de l'état pour la liste d'adresses : la clé courante après
/// une éventuelle rotation déjà vérifiée.
#[derive(Debug, Clone, Deserialize)]
pub struct EtatCle {
    #[serde(default)]
    pub cle: String,
}

/// Source des octets : Tor en production, une table en test.
trait Source {
    fn get(&self, url: &str, max: usize) -> Result<Vec<u8>, String>;
}

/// Exécution locale : installateur NSIS et interrogation du service.
trait Hote {
    fn lancer(&self, programme: &Path) -> Result<(), String>;
    fn service_actif(&self) -> bool;
}

struct TorSource {
    doh: ClientDoh,
}

impl Source for TorSource {
    fn get(&self, url: &str, max: usize) -> Result<Vec<u8>, String> {
        let chemin = chemin_local(url, &self.doh.hote())?;
        self.doh.get(&chemin, max)
    }
}

struct HoteReel;

impl Hote for HoteReel {
    fn lancer(&self, programme: &Path) -> Result<(), String> {
        let statut = std::process::Command::new(programme)
            .arg("/S")
            .status()
            .map_err(|e| format!("lancement de {} : {e}", programme.display()))?;
        if !statut.success() {
            return Err(format!("installateur terminé avec {}", statut));
        }
        Ok(())
    }

    fn service_actif(&self) -> bool {
        let Ok(sortie) = std::process::Command::new("sc").args(["query", "TorDNS"]).output() else {
            return false;
        };
        let texte = String::from_utf8_lossy(&sortie.stdout).to_ascii_uppercase();
        texte.contains("RUNNING")
    }
}

/// Vérifie que l'URL appartient bien au nœud Tor configuré et renvoie son
/// chemin. Une URL vers un autre hôte est refusée : le manifeste signé ne doit
/// pas pouvoir faire sortir le client du réseau Tor.
fn chemin_local(url: &str, onion: &str) -> Result<String, String> {
    let reste = url
        .strip_prefix("http://")
        .ok_or_else(|| format!("URL non HTTP : {url}"))?;
    let (hote, chemin) = reste
        .split_once('/')
        .ok_or_else(|| format!("URL sans chemin : {url}"))?;
    if hote != onion {
        return Err(format!("URL vers un autre hôte que {onion} : {hote}"));
    }
    let chemin = format!("/{chemin}");
    if chemin.contains(char::is_whitespace) {
        return Err("chemin HTTP invalide".into());
    }
    Ok(chemin)
}

/// Point d'entrée du service : configuration réelle, Tor et Windows.
pub fn executer_reel(chemin_config: &Path) -> Result<(), String> {
    let config = Config::charger(chemin_config)?;
    let c = ConfigMaj::depuis(&config);
    if c.manifeste_url.is_empty() {
        return Err("TORDNS_MAJ_MANIFESTE absent : aucune source de mise à jour".into());
    }
    if c.onion.is_empty() {
        return Err("adresse .onion absente de la configuration".into());
    }
    // Défense en profondeur (relecture du 23/11) : on ne fait confiance à maj\ (état, clé de
    // rotation, installateurs) qu'après avoir re-verrouillé ses droits nous-mêmes, en SYSTEM.
    let racine = c
        .etat
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| "dossier TorDNS introuvable".to_string())?;
    verrouiller_dossier(racine)?;
    let doh = ClientDoh::new(&c.socks, &c.onion, c.delai)?;
    let source = TorSource { doh };
    appliquer(&c, &source, &HoteReel)
}

/// Propriétaire Administrateurs, héritage coupé, écriture SYSTEM/Administrateurs seulement.
/// Un fichier posé par un utilisateur avant le verrouillage perd ainsi ses droits de
/// propriétaire. Échec = pas de mise à jour.
fn verrouiller_dossier(dossier: &Path) -> Result<(), String> {
    let d = dossier.to_string_lossy().to_string();
    let etoile = format!("{}\\*", d.trim_end_matches('\\'));
    let etapes: [Vec<&str>; 3] = [
        vec![&d, "/setowner", "*S-1-5-32-544", "/T", "/C", "/Q"],
        vec![
            &d,
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-18:(OI)(CI)F",
            "*S-1-5-32-544:(OI)(CI)F",
            "*S-1-5-32-545:(OI)(CI)RX",
            "/Q",
        ],
        vec![&etoile, "/reset", "/T", "/C", "/Q"],
    ];
    for args in etapes.iter() {
        let statut = std::process::Command::new("icacls")
            .args(args)
            .status()
            .map_err(|e| format!("icacls : {e}"))?;
        // /reset sur un dossier vide (aucun fichier pour *) n'est pas une erreur.
        if !statut.success() && args[1] != "/reset" {
            return Err(format!("verrouillage des droits de {d} impossible ({statut})"));
        }
    }
    Ok(())
}

fn appliquer(c: &ConfigMaj, source: &dyn Source, hote: &dyn Hote) -> Result<(), String> {
    let etat = lire_etat(&c.etat)?;
    let brut = source.get(&c.manifeste_url, tordns_manifeste::TAILLE_MAX_MANIFESTE)?;
    let sig = source.get(&c.signature_url, 4096)?;
    let cle = if etat.cle.is_empty() { &c.cle } else { &etat.cle };
    let m = tordns_manifeste::accepter(
        &brut,
        &sig,
        cle,
        etat.version,
        tordns_manifeste::maintenant(),
    )
    .map_err(|e| e.to_string())?;

    let cible = m
        .cibles
        .get(&c.cible)
        .ok_or_else(|| format!("cible {:?} absente du manifeste", c.cible))?;
    if !c.installateur.is_file() {
        return Err(format!(
            "aucun installateur précédent dans {} : retour arrière impossible",
            c.installateur.display()
        ));
    }
    let nouveau = source.get(&cible.url, TAILLE_MAX_INSTALLATEUR)?;
    if nouveau.len() as i64 != cible.taille {
        return Err(format!(
            "taille de l'installateur : {} octets, attendu {}",
            nouveau.len(),
            cible.taille
        ));
    }
    let somme = hex::encode(Sha256::digest(&nouveau));
    if somme != cible.sha256 {
        return Err("SHA-256 de l'installateur différent du manifeste".into());
    }

    let dossier = c
        .installateur
        .parent()
        .ok_or_else(|| "chemin d'installateur sans dossier".to_string())?;
    fs::create_dir_all(dossier).map_err(|e| format!("création de {} : {e}", dossier.display()))?;
    let temporaire = c.installateur.with_extension("nouveau.exe");
    // Jamais réécrire un fichier déjà là (il pourrait appartenir à un autre que nous) :
    // on le supprime puis on crée un fichier neuf, en exclusivité.
    let _ = fs::remove_file(&temporaire);
    {
        use std::io::Write;
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporaire)
            .map_err(|e| format!("création de {} : {e}", temporaire.display()))?;
        f.write_all(&nouveau)
            .and_then(|_| f.sync_all())
            .map_err(|e| format!("écriture de {} : {e}", temporaire.display()))?;
    }
    fs::copy(&c.installateur, &c.cache).map_err(|e| {
        format!(
            "copie de secours {} -> {} : {e}",
            c.installateur.display(),
            c.cache.display()
        )
    })?;
    fs::rename(&temporaire, &c.installateur)
        .map_err(|e| format!("installation de {} : {e}", c.installateur.display()))?;

    if let Err(e) = hote.lancer(&c.installateur) {
        return retour_arriere(c, hote, &e);
    }
    if !hote.service_actif() {
        return retour_arriere(c, hote, "le service TorDNS ne redémarre pas");
    }

    // Le manifeste et sa signature sont conservés pour la liste d'adresses :
    // ils ne sont écrits qu'après une installation réussie.
    fs::write(&c.manifeste_cache, &brut)
        .map_err(|e| format!("cache du manifeste : {e}"))?;
    fs::write(&c.signature_cache, &sig)
        .map_err(|e| format!("cache de la signature : {e}"))?;

    let mut nouvel = Etat {
        version: m.version,
        cle: etat.cle,
    };
    if !m.cle_suivante.is_empty() {
        nouvel.cle = m.cle_suivante;
    }
    ecrire_etat(&c.etat, &nouvel)?;
    println!("Client Windows mis à jour en v{}.", m.version);
    Ok(())
}

fn retour_arriere(c: &ConfigMaj, hote: &dyn Hote, cause: &str) -> Result<(), String> {
    println!("Mise à jour refusée ({cause}) : retour à l'installateur précédent.");
    hote.lancer(&c.cache)
        .map_err(|e| format!("retour arrière impossible : {e} (cause : {cause})"))?;
    if !hote.service_actif() {
        return Err(format!(
            "l'ancienne version ne redémarre pas non plus (cause : {cause})"
        ));
    }
    Err(format!("mise à jour rejetée, version précédente rétablie : {cause}"))
}

fn lire_etat(chemin: &Path) -> Result<Etat, String> {
    match fs::read(chemin) {
        Ok(brut) => serde_json::from_slice(&brut).map_err(|e| format!("état illisible : {e}")),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Etat::default()),
        Err(e) => Err(format!("état illisible : {e}")),
    }
}

fn ecrire_etat(chemin: &Path, etat: &Etat) -> Result<(), String> {
    if let Some(dossier) = chemin.parent() {
        fs::create_dir_all(dossier).map_err(|e| format!("création de l'état : {e}"))?;
    }
    let brut = serde_json::to_vec_pretty(etat).map_err(|e| format!("état : {e}"))?;
    let tmp = chemin.with_extension("json.tmp");
    fs::write(&tmp, brut).map_err(|e| format!("écriture de l'état : {e}"))?;
    fs::rename(&tmp, chemin).map_err(|e| format!("état : {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::cell::{Cell, RefCell};
    use std::collections::HashMap;

    struct FausseSource {
        reponses: HashMap<String, Vec<u8>>,
    }

    impl Source for FausseSource {
        fn get(&self, url: &str, max: usize) -> Result<Vec<u8>, String> {
            let octets = self
                .reponses
                .get(url)
                .cloned()
                .ok_or_else(|| format!("404 pour {url}"))?;
            if octets.len() > max {
                return Err("trop gros".into());
            }
            Ok(octets)
        }
    }

    #[derive(Default)]
    struct FauxHote {
        lancements: RefCell<Vec<PathBuf>>,
        actif: Cell<bool>,
        echec_installateur: bool,
    }

    impl Hote for FauxHote {
        fn lancer(&self, programme: &Path) -> Result<(), String> {
            self.lancements.borrow_mut().push(programme.to_path_buf());
            if self.echec_installateur {
                return Err("installateur en échec".into());
            }
            // La première version ne redémarre pas ; le retour arrière, si,
            // ce qui permet de distinguer les deux issues.
            if self.lancements.borrow().len() >= 2 {
                self.actif.set(true);
            }
            Ok(())
        }

        fn service_actif(&self) -> bool {
            self.actif.get()
        }
    }

    fn manifeste_json(version: i64, url: &str, taille: usize, sha: &str) -> String {
        format!(
            r#"{{"version":{version},"expire":"2030-01-01T00:00:00Z","cibles":{{"client-windows":{{"url":"{url}","taille":{taille},"sha256":"{sha}"}}}}}}"#
        )
    }

    fn cle_de_test() -> (SigningKey, String) {
        let cle = SigningKey::from_bytes(&[9u8; 32]);
        let publique = cle.verifying_key().to_bytes();
        (cle, hex::encode(publique))
    }

    fn preparer(version: i64) -> (ConfigMaj, SigningKey) {
        // Les tests tournent en parallèle : chaque dossier doit être unique.
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dossier = std::env::temp_dir().join(format!(
            "tordns-maj-win-{}-{version}-{unique}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dossier);
        fs::create_dir_all(&dossier).unwrap();
        let installateur = dossier.join("TorDNS-setup.exe");
        fs::write(&installateur, b"ancien").unwrap();
        let (cle, publique) = cle_de_test();
        let c = ConfigMaj {
            manifeste_url: "http://exemple.onion/maj/manifeste.json".into(),
            signature_url: "http://exemple.onion/maj/manifeste.json.sig".into(),
            socks: "127.0.0.1:9050".into(),
            onion: "exemple.onion".into(),
            cible: "client-windows".into(),
            installateur,
            cache: dossier.join("precedent.exe"),
            etat: dossier.join("maj.json"),
            manifeste_cache: dossier.join("manifeste.json"),
            signature_cache: dossier.join("manifeste.json.sig"),
            cle: publique,
            delai: Duration::from_secs(1),
        };
        (c, cle)
    }

    fn source_signee(c: &ConfigMaj, cle: &SigningKey, version: i64, contenu: &[u8], modif_sha: bool) -> FausseSource {
        let url = "http://exemple.onion/maj/x";
        let sha = if modif_sha {
            "b".repeat(64)
        } else {
            hex::encode(Sha256::digest(contenu))
        };
        let brut = manifeste_json(version, url, contenu.len(), &sha).into_bytes();
        let signature = cle.sign(&brut).to_bytes().to_vec();
        FausseSource {
            reponses: HashMap::from([
                (c.manifeste_url.clone(), brut),
                (c.signature_url.clone(), signature),
                (url.into(), contenu.to_vec()),
            ]),
        }
    }

    #[test]
    fn telechargement_refuse_hors_du_noeud() {
        assert!(chemin_local("http://autre.onion/x", "exemple.onion").is_err());
        assert_eq!(
            chemin_local("http://exemple.onion/maj/x", "exemple.onion").unwrap(),
            "/maj/x"
        );
        assert!(chemin_local("https://exemple.onion/x", "exemple.onion").is_err());
    }

    #[test]
    fn refus_sans_installateur_precedent() {
        let (c, cle) = preparer(2);
        fs::remove_file(&c.installateur).unwrap();
        let source = source_signee(&c, &cle, 2, b"nouveau", false);
        let hote = FauxHote::default();
        let err = appliquer(&c, &source, &hote).unwrap_err();
        assert!(err.contains("retour arrière impossible"), "{err}");
    }

    #[test]
    fn refuse_un_installateur_altere() {
        let (c, cle) = preparer(2);
        let source = source_signee(&c, &cle, 2, b"nouveau", true);
        let hote = FauxHote::default();
        let err = appliquer(&c, &source, &hote).unwrap_err();
        assert!(err.contains("SHA-256"), "{err}");
        assert!(hote.lancements.borrow().is_empty());
    }

    #[test]
    fn accepte_puis_retour_arriere_si_service_mort() {
        let (c, cle) = preparer(2);
        // Service qui ne redémarre pas : les deux installateurs sont lancés,
        // d'abord le nouveau puis le précédent.
        let hote = FauxHote {
            lancements: RefCell::new(Vec::new()),
            actif: Cell::new(false),
            echec_installateur: false,
        };
        let source = source_signee(&c, &cle, 2, b"nouveau", false);
        let err = appliquer(&c, &source, &hote).unwrap_err();
        assert!(err.contains("version précédente rétablie"), "{err}");
        let lancements = hote.lancements.borrow();
        assert_eq!(lancements.len(), 2);
        assert_eq!(lancements[0], c.installateur);
        assert_eq!(lancements[1], c.cache);
        assert_eq!(lire_etat(&c.etat).unwrap().version, 0);
    }

    #[test]
    fn applique_une_version_signee_et_refuse_le_rejeu() {
        let (c, cle) = preparer(2);
        let source = source_signee(&c, &cle, 2, b"nouveau", false);
        let hote = FauxHote {
            actif: Cell::new(true),
            ..FauxHote::default()
        };
        appliquer(&c, &source, &hote).unwrap();
        assert_eq!(lire_etat(&c.etat).unwrap().version, 2);
        assert_eq!(fs::read(&c.cache).unwrap(), b"ancien");
        let err = appliquer(&c, &source, &hote).unwrap_err();
        assert!(err.contains("déjà installée"), "{err}");
    }

    // Relecture du 23/11 : un fichier « nouveau » posé d'avance (par un autre utilisateur)
    // n'est jamais réutilisé tel quel ; il est remplacé par un fichier neuf.
    #[test]
    fn ne_reutilise_pas_un_fichier_temporaire_pose_d_avance() {
        let (c, cle) = preparer(3);
        let temporaire = c.installateur.with_extension("nouveau.exe");
        fs::write(&temporaire, b"piege-pose-par-un-utilisateur-plus-long").unwrap();
        let source = source_signee(&c, &cle, 3, b"nouveau", false);
        let hote = FauxHote {
            actif: Cell::new(true),
            ..FauxHote::default()
        };
        appliquer(&c, &source, &hote).unwrap();
        assert_eq!(fs::read(&c.installateur).unwrap(), b"nouveau");
        assert!(!temporaire.exists());
    }

    #[test]
    fn ecrit_et_lit_etat() {
        let dossier = std::env::temp_dir().join(format!("tordns-etat-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dossier);
        let chemin = dossier.join("maj.json");
        assert_eq!(lire_etat(&chemin).unwrap().version, 0);
        ecrire_etat(
            &chemin,
            &Etat {
                version: 3,
                cle: "ab".into(),
            },
        )
        .unwrap();
        let relu = lire_etat(&chemin).unwrap();
        assert_eq!(relu.version, 3);
        assert_eq!(relu.cle, "ab");
    }


}
