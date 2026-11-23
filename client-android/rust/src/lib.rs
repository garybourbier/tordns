//! Pont JNI entre l'application Android et Arti.
//!
//! L'application ne parle jamais au réseau elle-même : ce crate maintient un
//! client Tor (Arti) et expose deux appels bloquants, utilisés depuis des
//! threads Java dédiés :
//!   - `demarrer` : bootstrap (long, 20 à 90 s) ;
//!   - `doh` : un POST DoH vers `<onion>:80`, via un circuit Tor.
//!
//! Aucun nom de domaine n'est journalisé, aucune donnée n'est écrite hors des
//! répertoires d'état/cache fournis par l'application.

use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use arti_client::config::TorClientConfigBuilder;
use arti_client::TorClient;
use futures::io::{AsyncReadExt, AsyncWriteExt};
use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jbyteArray, jint, jlong, jstring};
use jni::JNIEnv;
use tokio::runtime::Runtime;
use tor_rtcompat::PreferredRuntime;

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

/// Lit une chaîne Java, en refusant les octets invalides.
fn chaine(env: &mut JNIEnv, valeur: &JString) -> Result<String, String> {
    env.get_string(valeur)
        .map(|s| s.into())
        .map_err(|e| format!("chaîne JNI invalide : {e}"))
}

fn demarrer_bloquant(state: &str, cache: &str) -> Result<(), String> {
    // Arti est compilé avec rustls sans fournisseur implicite : on installe ring.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let rt = runtime()?;
    let config = TorClientConfigBuilder::from_directories(Path::new(state), Path::new(cache))
        .build()
        .map_err(|e| format!("configuration Arti : {e}"))?;

    let client = rt
        .block_on(async {
            tokio::time::timeout(
                Duration::from_secs(180),
                TorClient::create_bootstrapped(config),
            )
            .await
        })
        .map_err(|_| "bootstrap Tor interrompu après 180 s".to_string())?
        .map_err(|e| format!("bootstrap Tor : {e}"))?;

    *client_slot()
        .lock()
        .map_err(|_| "verrou du client Tor empoisonné".to_string())? = Some(client);
    Ok(())
}

/// Ouvre une connexion Tor vers `onion:80` et renvoie la réponse DoH brute.
fn doh_bloquant(onion: &str, requete: &[u8], delai: Duration) -> Result<Vec<u8>, String> {
    if requete.is_empty() {
        return Err("requête DNS vide".into());
    }
    if !onion.ends_with(".onion") || onion.len() < 8 {
        return Err("adresse .onion invalide".into());
    }
    let garde = client_slot()
        .lock()
        .map_err(|_| "verrou du client Tor empoisonné".to_string())?;
    let client = garde
        .as_ref()
        .cloned()
        .ok_or("Tor n'est pas encore démarré")?;
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
                 User-Agent: TorDNS-Android/0.1\r\n\
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
fn telecharger_bloquant(onion: &str, chemin: &str, max: usize) -> Result<Vec<u8>, String> {
    if !onion.ends_with(".onion") || onion.len() < 8 {
        return Err("adresse .onion invalide".into());
    }
    if !chemin.starts_with('/') || chemin.contains(char::is_whitespace) {
        return Err("chemin HTTP invalide".into());
    }
    let garde = client_slot()
        .lock()
        .map_err(|_| "verrou du client Tor empoisonné".to_string())?;
    let client = garde
        .as_ref()
        .cloned()
        .ok_or("Tor n'est pas encore démarré")?;
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
                 User-Agent: TorDNS-Android/0.1\r\nConnection: close\r\n\r\n"
            );
            flux.write_all(entete.as_bytes())
                .await
                .map_err(|e| format!("écriture HTTP : {e}"))?;
            flux.flush().await.map_err(|e| format!("écriture HTTP : {e}"))?;

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

#[no_mangle]
pub extern "system" fn Java_org_tordns_client_Arti_demarrer(
    mut env: JNIEnv,
    _classe: JClass,
    etat: JString,
    cache: JString,
) -> jstring {
    let resultat = (|| {
        let etat = chaine(&mut env, &etat)?;
        let cache = chaine(&mut env, &cache)?;
        demarrer_bloquant(&etat, &cache)
    })();

    match resultat {
        Ok(()) => std::ptr::null_mut(),
        Err(e) => {
            let message = note_erreur(e);
            env.new_string(message)
                .map(|s| s.into_raw())
                .unwrap_or(std::ptr::null_mut())
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_org_tordns_client_Arti_doh(
    mut env: JNIEnv,
    _classe: JClass,
    onion: JString,
    requete: JByteArray,
    delai_ms: jint,
) -> jbyteArray {
    let resultat = (|| {
        let onion = chaine(&mut env, &onion)?;
        let octets = env
            .convert_byte_array(&requete)
            .map_err(|e| format!("requête JNI invalide : {e}"))?;
        let delai = Duration::from_millis(delai_ms.max(1000) as u64);
        doh_bloquant(&onion, &octets, delai)
    })();

    match resultat {
        Ok(corps) => match env.byte_array_from_slice(&corps) {
            Ok(arr) => arr.into_raw(),
            Err(e) => {
                note_erreur(format!("allocation JNI : {e}"));
                std::ptr::null_mut()
            }
        },
        Err(e) => {
            note_erreur(e);
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_org_tordns_client_Arti_verifierManifeste(
    env: JNIEnv,
    _classe: JClass,
    manifeste: JByteArray,
    signature: JByteArray,
    version_installee: jlong,
    maintenant: jlong,
) -> jstring {
    let resultat: Result<String, String> = (|| {
        let brut = env
            .convert_byte_array(&manifeste)
            .map_err(|e| format!("manifeste JNI invalide : {e}"))?;
        let sig = env
            .convert_byte_array(&signature)
            .map_err(|e| format!("signature JNI invalide : {e}"))?;
        let m = tordns_manifeste::accepter(
            &brut,
            &sig,
            tordns_manifeste::CLE_PUBLIQUE_EPINGLEE,
            version_installee as i64,
            maintenant as i64,
        )
        .map_err(|e| e.to_string())?;
        let c = m
            .cibles
            .get("client-android")
            .ok_or_else(|| "cible client-android absente du manifeste".to_string())?;
        Ok(format!(
            "{}|{}|{}|{}|{}|{}|{}",
            m.version,
            c.url,
            c.taille,
            c.sha256,
            m.cle_suivante,
            m.adresses.get("coeur").map(String::as_str).unwrap_or(""),
            m.adresses
                .get("communaute")
                .map(String::as_str)
                .unwrap_or("")
        ))
    })();
    match resultat {
        Ok(record) => env
            .new_string(record)
            .map(|s| s.into_raw())
            .unwrap_or(std::ptr::null_mut()),
        Err(e) => {
            let message = note_erreur(e);
            env.new_string(message)
                .map(|s| s.into_raw())
                .unwrap_or(std::ptr::null_mut())
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_org_tordns_client_Arti_telecharger(
    mut env: JNIEnv,
    _classe: JClass,
    onion: JString,
    chemin: JString,
    max: jint,
) -> jbyteArray {
    let resultat = (|| {
        let onion = chaine(&mut env, &onion)?;
        let chemin = chaine(&mut env, &chemin)?;
        if max <= 0 {
            return Err("taille maximale invalide".into());
        }
        telecharger_bloquant(&onion, &chemin, max as usize)
    })();
    match resultat {
        Ok(corps) => match env.byte_array_from_slice(&corps) {
            Ok(arr) => arr.into_raw(),
            Err(e) => {
                note_erreur(format!("allocation JNI : {e}"));
                std::ptr::null_mut()
            }
        },
        Err(e) => {
            note_erreur(e);
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_org_tordns_client_Arti_derniereErreur(
    env: JNIEnv,
    _classe: JClass,
) -> jstring {
    let message = erreur()
        .lock()
        .map(|s| s.clone())
        .unwrap_or_else(|_| "erreur inconnue".into());
    env.new_string(message)
        .map(|s| s.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub extern "system" fn Java_org_tordns_client_Arti_arreter(_env: JNIEnv, _classe: JClass) {
    if let Ok(mut slot) = client_slot().lock() {
        *slot = None;
    }
    let _ = RUNTIME.get();
}

/// Utilisé par l'exemple hôte (`--example doh`) pour vérifier le chemin DoH
/// complet sans Android.
pub fn doh_hote(onion: &str, requete: &[u8], delai: Duration) -> Result<Vec<u8>, String> {
    doh_bloquant(onion, requete, delai)
}

pub fn demarrer_hote(state: &str, cache: &str) -> Result<(), String> {
    demarrer_bloquant(state, cache)
}
