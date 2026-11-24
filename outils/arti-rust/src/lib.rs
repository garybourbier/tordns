//! Client Tor (Arti) et DoH vers le service caché TorDNS.
//!
//! Ce crate ne connaît ni Android ni iOS : il maintient un client Tor et
//! expose trois appels bloquants, que chaque plateforme emballe dans son propre
//! pont (`client-android/rust` par JNI, `client-ios/rust` par ABI C) :
//!   - [`demarrer`] : bootstrap (long, 20 à 90 s) ;
//!   - [`doh`] : un POST DoH vers `<onion>:80`, via un circuit Tor ;
//!   - [`telecharger`] : un GET borné vers `<onion>:80` (manifeste, APK).
//!
//! Aucun nom de domaine n'est journalisé, aucune donnée n'est écrite hors des
//! répertoires d'état/cache fournis par l'application.

use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use arti_client::config::TorClientConfigBuilder;
use arti_client::TorClient;
use futures::io::{AsyncReadExt, AsyncWriteExt};
use tokio::runtime::Runtime;
use tor_rtcompat::PreferredRuntime;

/// Nom annoncé aux miroirs TorDNS. Il ne porte aucune donnée personnelle.
const AGENT: &str = concat!("TorDNS/", env!("CARGO_PKG_VERSION"), " (Arti)");

/// Délai de bootstrap : au-delà, on rend la main à l'application.
const DELAI_BOOTSTRAP: Duration = Duration::from_secs(180);

static CLIENT: OnceLock<Mutex<Option<Arc<TorClient<PreferredRuntime>>>>> = OnceLock::new();
static RUNTIME: OnceLock<Runtime> = OnceLock::new();
static DERNIERE_ERREUR: OnceLock<Mutex<String>> = OnceLock::new();

fn client_slot() -> &'static Mutex<Option<Arc<TorClient<PreferredRuntime>>>> {
    CLIENT.get_or_init(|| Mutex::new(None))
}

fn erreur() -> &'static Mutex<String> {
    DERNIERE_ERREUR.get_or_init(|| Mutex::new(String::new()))
}

fn runtime() -> Result<&'static Runtime, String> {
    if let Some(rt) = RUNTIME.get() {
        return Ok(rt);
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .thread_name("arti")
        .build()
        .map_err(|e| format!("runtime : {e}"))?;
    Ok(RUNTIME.get_or_init(|| rt))
}

fn note_erreur(message: impl Into<String>) -> String {
    let message = message.into();
    if let Ok(mut slot) = erreur().lock() {
        *slot = message.clone();
    }
    message
}

/// Dernière erreur rencontrée, pour l'afficher à l'utilisateur.
pub fn derniere_erreur() -> String {
    erreur()
        .lock()
        .map(|s| s.clone())
        .unwrap_or_else(|_| "erreur inconnue".into())
}

/// Vrai si un client Tor est bootstrappé et prêt à porter des requêtes.
pub fn demarre() -> bool {
    client_slot()
        .lock()
        .map(|slot| slot.is_some())
        .unwrap_or(false)
}

/// Refuse tout ce qui n'est pas une adresse `.onion` plausible.
fn verifier_onion(onion: &str) -> Result<(), String> {
    if !onion.ends_with(".onion") || onion.len() < 8 {
        return Err("adresse .onion invalide".into());
    }
    if onion.contains(char::is_whitespace) || onion.contains('/') {
        return Err("adresse .onion invalide".into());
    }
    Ok(())
}

fn client() -> Result<Arc<TorClient<PreferredRuntime>>, String> {
    client_slot()
        .lock()
        .map_err(|_| "verrou du client Tor empoisonné".to_string())?
        .as_ref()
        .cloned()
        .ok_or_else(|| "Tor n'est pas encore démarré".to_string())
}

/// Bootstrap d'Arti, avec les répertoires d'état et de cache fournis par
/// l'application (bac à sable iOS, stockage interne Android).
pub fn demarrer(etat: &str, cache: &str) -> Result<(), String> {
    demarrer_avec_delai(etat, cache, DELAI_BOOTSTRAP)
}

/// Variante avec délai explicite, utilisée par les tests et les diagnostics.
pub fn demarrer_avec_delai(etat: &str, cache: &str, delai: Duration) -> Result<(), String> {
    // Arti est compilé avec rustls sans fournisseur implicite : on installe ring.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let rt = runtime()?;
    let config = TorClientConfigBuilder::from_directories(Path::new(etat), Path::new(cache))
        .build()
        .map_err(|e| note_erreur(format!("configuration Arti : {e}")))?;

    let client = rt
        .block_on(async {
            tokio::time::timeout(delai, TorClient::create_bootstrapped(config)).await
        })
        .map_err(|_| note_erreur("bootstrap Tor interrompu".to_string()))?
        .map_err(|e| note_erreur(format!("bootstrap Tor : {e}")))?;

    *client_slot()
        .lock()
        .map_err(|_| "verrou du client Tor empoisonné".to_string())? = Some(client);
    Ok(())
}

/// Ouvre une connexion Tor vers `onion:80` et renvoie la réponse DoH brute.
pub fn doh(onion: &str, requete: &[u8], delai: Duration) -> Result<Vec<u8>, String> {
    if requete.is_empty() {
        return Err("requête DNS vide".into());
    }
    verifier_onion(onion)?;
    let client = client()?;
    let rt = runtime()?;

    let onion = onion.to_string();
    let requete = requete.to_vec();
    rt.block_on(async move {
        tokio::time::timeout(delai, async move {
            let mut flux = client
                .connect((onion.as_str(), 80u16))
                .await
                .map_err(|e| format!("connexion au service caché : {e}"))?;

            let entete = format!(
                "POST /dns-query HTTP/1.1\r\n\
                 Host: {onion}\r\n\
                 Content-Type: application/dns-message\r\n\
                 Accept: application/dns-message\r\n\
                 Content-Length: {}\r\n\
                 User-Agent: {AGENT}\r\n\
                 Connection: close\r\n\r\n",
                requete.len()
            );
            flux.write_all(entete.as_bytes())
                .await
                .map_err(|e| format!("écriture DoH : {e}"))?;
            flux.write_all(&requete)
                .await
                .map_err(|e| format!("écriture DoH : {e}"))?;
            flux.flush()
                .await
                .map_err(|e| format!("écriture DoH : {e}"))?;

            let mut tampon = Vec::with_capacity(4096);
            let mut bloc = [0u8; 4096];
            // En-têtes HTTP.
            let fin_entetes = loop {
                let n = flux
                    .read(&mut bloc)
                    .await
                    .map_err(|e| format!("lecture DoH : {e}"))?;
                if n == 0 {
                    return Err("réponse DoH tronquée (en-têtes)".to_string());
                }
                tampon.extend_from_slice(&bloc[..n]);
                if let Some(p) = trouver(&tampon, b"\r\n\r\n") {
                    break p + 4;
                }
                if tampon.len() > 16 * 1024 {
                    return Err("en-têtes DoH trop volumineux".into());
                }
            };

            let statut = std::str::from_utf8(&tampon[..fin_entetes])
                .map_err(|_| "en-têtes DoH non UTF-8".to_string())?
                .lines()
                .next()
                .unwrap_or("")
                .to_string();
            if !statut.contains(" 200 ") {
                return Err(format!("DoH a répondu « {} »", statut.trim()));
            }

            let longueur = content_length(&tampon[..fin_entetes])?;
            if longueur > 64 * 1024 {
                return Err("réponse DoH trop volumineuse".into());
            }
            let mut corps = tampon.split_off(fin_entetes);
            while corps.len() < longueur {
                let n = flux
                    .read(&mut bloc)
                    .await
                    .map_err(|e| format!("lecture DoH : {e}"))?;
                if n == 0 {
                    return Err("réponse DoH tronquée (corps)".to_string());
                }
                corps.extend_from_slice(&bloc[..n]);
            }
            corps.truncate(longueur);
            Ok(corps)
        })
        .await
        .map_err(|_| "délai DoH dépassé".to_string())?
    })
}

/// Télécharge une ressource du miroir (`/maj/…`) par le circuit Tor, en HTTP
/// GET. Le corps est borné : un manifeste ou un APK plus gros est refusé.
pub fn telecharger(onion: &str, chemin: &str, max: usize) -> Result<Vec<u8>, String> {
    verifier_onion(onion)?;
    if !chemin.starts_with('/') || chemin.contains(char::is_whitespace) {
        return Err("chemin HTTP invalide".into());
    }
    if max == 0 {
        return Err("taille maximale invalide".into());
    }
    let client = client()?;
    let rt = runtime()?;
    let onion = onion.to_string();
    let chemin = chemin.to_string();
    rt.block_on(async move {
        tokio::time::timeout(Duration::from_secs(120), async move {
            let mut flux = client
                .connect((onion.as_str(), 80u16))
                .await
                .map_err(|e| format!("connexion au service caché : {e}"))?;
            let entete = format!(
                "GET {chemin} HTTP/1.1\r\nHost: {onion}\r\nAccept: */*\r\n\
                 User-Agent: {AGENT}\r\nConnection: close\r\n\r\n"
            );
            flux.write_all(entete.as_bytes())
                .await
                .map_err(|e| format!("écriture HTTP : {e}"))?;
            flux.flush()
                .await
                .map_err(|e| format!("écriture HTTP : {e}"))?;

            let mut tampon = Vec::with_capacity(4096);
            let mut bloc = [0u8; 4096];
            let fin_entetes = loop {
                let n = flux
                    .read(&mut bloc)
                    .await
                    .map_err(|e| format!("lecture HTTP : {e}"))?;
                if n == 0 {
                    return Err("réponse HTTP tronquée (en-têtes)".to_string());
                }
                tampon.extend_from_slice(&bloc[..n]);
                if let Some(p) = trouver(&tampon, b"\r\n\r\n") {
                    break p + 4;
                }
                if tampon.len() > 16 * 1024 {
                    return Err("en-têtes HTTP trop volumineux".into());
                }
            };
            let statut = std::str::from_utf8(&tampon[..fin_entetes])
                .map_err(|_| "en-têtes HTTP non UTF-8".to_string())?
                .lines()
                .next()
                .unwrap_or("")
                .to_string();
            if !statut.contains(" 200 ") {
                return Err(format!("HTTP a répondu « {} »", statut.trim()));
            }
            let longueur = content_length(&tampon[..fin_entetes])?;
            if longueur > max {
                return Err(format!("ressource trop volumineuse ({longueur} octets)"));
            }
            let mut corps = tampon.split_off(fin_entetes);
            while corps.len() < longueur {
                let n = flux
                    .read(&mut bloc)
                    .await
                    .map_err(|e| format!("lecture HTTP : {e}"))?;
                if n == 0 {
                    return Err("réponse HTTP tronquée (corps)".to_string());
                }
                corps.extend_from_slice(&bloc[..n]);
                if corps.len() > max {
                    return Err("ressource trop volumineuse".into());
                }
            }
            corps.truncate(longueur);
            Ok(corps)
        })
        .await
        .map_err(|_| "délai HTTP dépassé".to_string())?
    })
}

/// Ferme le client Tor et rend les circuits. L'application garde la main sur
/// son état : un `demarrer` ultérieur rebootstrappe.
pub fn arreter() {
    if let Ok(mut slot) = client_slot().lock() {
        *slot = None;
    }
}

fn trouver(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn content_length(entetes: &[u8]) -> Result<usize, String> {
    let texte = std::str::from_utf8(entetes).map_err(|_| "en-têtes non UTF-8".to_string())?;
    for ligne in texte.lines().skip(1) {
        if let Some((nom, valeur)) = ligne.split_once(':') {
            if nom.eq_ignore_ascii_case("content-length") {
                return valeur
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| "Content-Length invalide".to_string());
            }
        }
    }
    Err("réponse DoH sans Content-Length".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONION: &str = "exempleexempleexempleexempleexempleexempleexempleexemple.onion";

    #[test]
    fn adresses_onion_acceptees_et_refusees() {
        assert!(verifier_onion(ONION).is_ok());
        for mauvais in [
            "",
            "a.onion",
            "exemple.onion ",
            "exemple onion",
            "exemple.onion/chemin",
            "exemple.fr",
        ] {
            assert!(
                verifier_onion(mauvais).is_err(),
                "« {mauvais} » aurait dû être refusé"
            );
        }
    }

    #[test]
    fn requete_vide_refusee_sans_reseau() {
        let e = doh(ONION, &[], Duration::from_secs(1)).unwrap_err();
        assert_eq!(e, "requête DNS vide");
    }

    #[test]
    fn chemin_invalide_refuse_sans_reseau() {
        assert_eq!(
            telecharger(ONION, "maj/manifeste", 1024).unwrap_err(),
            "chemin HTTP invalide"
        );
        assert_eq!(
            telecharger(ONION, "/maj/ manifeste", 1024).unwrap_err(),
            "chemin HTTP invalide"
        );
        assert_eq!(
            telecharger(ONION, "/maj/manifeste", 0).unwrap_err(),
            "taille maximale invalide"
        );
    }

    #[test]
    fn tor_non_demarre_refuse_la_requete() {
        arreter();
        let e = doh(ONION, &[0x12, 0x34], Duration::from_secs(1)).unwrap_err();
        assert_eq!(e, "Tor n'est pas encore démarré");
        assert!(!demarre());
    }

    #[test]
    fn en_tetes_http_analyses() {
        let entetes = b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: 42\r\n\r\n";
        assert_eq!(content_length(entetes).unwrap(), 42);
        let casse = b"HTTP/1.1 200 OK\r\ncontent-length:   7\r\n\r\n";
        assert_eq!(content_length(casse).unwrap(), 7);
        assert!(content_length(b"HTTP/1.1 200 OK\r\n\r\n").is_err());
        assert!(content_length(b"HTTP/1.1 200 OK\r\nContent-Length: gros\r\n\r\n").is_err());
    }

    #[test]
    fn corps_delimite_par_les_entetes() {
        let reponse = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc";
        let p = trouver(reponse, b"\r\n\r\n").unwrap();
        assert_eq!(&reponse[p + 4..], b"abc");
        assert_eq!(trouver(b"abcdef", b"zz"), None);
    }
}
