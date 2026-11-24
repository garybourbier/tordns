//! Pont JNI entre l'application Android et Arti.
//!
//! Toute la logique Tor et DoH vit dans `outils/arti-rust` (crate partagé avec
//! le client iOS) : ce fichier ne fait que traduire les types JNI et garder le
//! message de la dernière erreur pour l'afficher dans l'interface.

use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jbyteArray, jint, jlong, jstring};
use jni::JNIEnv;

static DERNIERE_ERREUR: OnceLock<Mutex<String>> = OnceLock::new();

fn erreur() -> &'static Mutex<String> {
    DERNIERE_ERREUR.get_or_init(|| Mutex::new(String::new()))
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
        tordns_tor::demarrer(&etat, &cache)
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
        tordns_tor::doh(&onion, &octets, delai)
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
        tordns_tor::telecharger(&onion, &chemin, max as usize)
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
    tordns_tor::arreter();
}
