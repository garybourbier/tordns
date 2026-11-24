//! Pont C entre l'application iOS et le crate Tor partagé (`tordns_tor`).
//!
//! Swift n'appelle pas Rust directement : cette bibliothèque statique expose
//! une ABI C stable (`include/tordns.h`), que l'extension réseau et
//! l'application lient via un module map. Toute la logique Tor, DoH et
//! vérification de manifeste vit dans `outils/arti-rust` et
//! `outils/manifeste-rust` : rien de réseau n'est réécrit ici.
//!
//! Règles de l'ABI, parce qu'un dépassement de tampon dans une extension
//! réseau iOS tue le processus sans message :
//!   - toute chaîne rendue par Rust est libérée par [`tordns_liberer_chaine`] ;
//!   - tout tampon rendu par Rust est libéré par [`tordns_liberer_reponse`] ;
//!   - tout pointeur nul ou longueur nulle est refusé sans paniquer.

use std::ffi::{c_char, CStr, CString};
use std::slice;
use std::time::Duration;

/// Réponse binaire : `code` vaut 0 (succès), -1 (Tor pas démarré) ou -2
/// (erreur, message disponible par [`tordns_derniere_erreur`]).
#[repr(C)]
pub struct TordnsReponse {
    pub donnees: *mut u8,
    pub longueur: usize,
    pub code: i32,
}

const CODE_OK: i32 = 0;
const CODE_TOR_ABSENT: i32 = -1;
const CODE_ERREUR: i32 = -2;

/// Délai maximal d'une requête DoH vue d'iOS : au-delà, le résolveur du
/// système a déjà rendu la main.
const DELAI_MAX_MS: u32 = 30_000;

fn chaine_entrante(pointeur: *const c_char) -> Result<String, String> {
    if pointeur.is_null() {
        return Err("chaîne nulle".into());
    }
    // SAFETY : l'appelant garantit une chaîne UTF-8 terminée par NUL.
    let texte = unsafe { CStr::from_ptr(pointeur) };
    texte
        .to_str()
        .map(|s| s.to_owned())
        .map_err(|_| "chaîne non UTF-8".to_string())
}

fn chaine_sortante(texte: String) -> *mut c_char {
    // Les NUL internes sont improbables (messages d'erreur) mais on ne laisse
    // pas un CString en échouer silencieusement.
    let propre = texte.replace('\0', " ");
    CString::new(propre)
        .map(|c| c.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

fn reponse(resultat: Result<Vec<u8>, String>) -> TordnsReponse {
    match resultat {
        Ok(mut corps) => {
            corps.shrink_to_fit();
            let longueur = corps.len();
            let donnees = corps.as_mut_ptr();
            std::mem::forget(corps);
            TordnsReponse {
                donnees,
                longueur,
                code: CODE_OK,
            }
        }
        Err(e) => TordnsReponse {
            donnees: std::ptr::null_mut(),
            longueur: 0,
            code: if e.contains("pas encore démarré") {
                CODE_TOR_ABSENT
            } else {
                CODE_ERREUR
            },
        },
    }
}

/// Bootstrap Tor. Rend NULL en cas de succès, sinon un message à libérer.
#[no_mangle]
pub extern "C" fn tordns_demarrer(etat: *const c_char, cache: *const c_char) -> *mut c_char {
    let resultat = (|| {
        let etat = chaine_entrante(etat)?;
        let cache = chaine_entrante(cache)?;
        tordns_tor::demarrer(&etat, &cache)
    })();
    match resultat {
        Ok(()) => std::ptr::null_mut(),
        Err(e) => chaine_sortante(e),
    }
}

/// Ferme Tor (l'extension réseau est suspendue, l'application garde l'état).
#[no_mangle]
pub extern "C" fn tordns_arreter() {
    tordns_tor::arreter();
}

/// 1 si Tor est bootstrappé, 0 sinon.
#[no_mangle]
pub extern "C" fn tordns_demarre() -> i32 {
    i32::from(tordns_tor::demarre())
}

/// POST DoH vers `<onion>:80` par un circuit Tor.
#[no_mangle]
pub extern "C" fn tordns_doh(
    onion: *const c_char,
    requete: *const u8,
    longueur: usize,
    delai_ms: u32,
) -> TordnsReponse {
    let resultat = (|| {
        let onion = chaine_entrante(onion)?;
        if requete.is_null() || longueur == 0 {
            return Err("requête DNS vide".into());
        }
        // SAFETY : l'appelant fournit `longueur` octets lisibles.
        let octets = unsafe { slice::from_raw_parts(requete, longueur) };
        let delai = Duration::from_millis(u64::from(delai_ms.clamp(1000, DELAI_MAX_MS)));
        tordns_tor::doh(&onion, octets, delai)
    })();
    reponse(resultat)
}

/// GET borné vers `<onion>:80` (manifeste, APK du miroir).
#[no_mangle]
pub extern "C" fn tordns_telecharger(
    onion: *const c_char,
    chemin: *const c_char,
    max: usize,
) -> TordnsReponse {
    let resultat = (|| {
        let onion = chaine_entrante(onion)?;
        let chemin = chaine_entrante(chemin)?;
        tordns_tor::telecharger(&onion, &chemin, max)
    })();
    reponse(resultat)
}

/// Vérifie le manifeste signé et rend
/// `version|url|taille|sha256|cle_suivante|coeur|secours|communaute`,
/// où les adresses absentes sont vides. Message d'erreur sinon.
#[no_mangle]
pub extern "C" fn tordns_verifier_manifeste(
    manifeste: *const u8,
    longueur_manifeste: usize,
    signature: *const u8,
    longueur_signature: usize,
    version_installee: i64,
    maintenant: i64,
) -> *mut c_char {
    let resultat: Result<String, String> = (|| {
        if manifeste.is_null() || longueur_manifeste == 0 {
            return Err("manifeste vide".into());
        }
        if signature.is_null() || longueur_signature == 0 {
            return Err("signature vide".into());
        }
        // SAFETY : l'appelant fournit ces longueurs d'octets lisibles.
        let brut = unsafe { slice::from_raw_parts(manifeste, longueur_manifeste) };
        let sig = unsafe { slice::from_raw_parts(signature, longueur_signature) };
        let m = tordns_manifeste::accepter(
            brut,
            sig,
            tordns_manifeste::CLE_PUBLIQUE_EPINGLEE,
            version_installee,
            maintenant,
        )
        .map_err(|e| e.to_string())?;
        let cible = m
            .cibles
            .get("client-ios")
            .or_else(|| m.cibles.get("client-android"))
            .ok_or_else(|| "aucune cible iOS dans le manifeste".to_string())?;
        let adresse = |nom: &str| m.adresses.get(nom).cloned().unwrap_or_default();
        Ok(format!(
            "{}|{}|{}|{}|{}|{}|{}|{}",
            m.version,
            cible.url,
            cible.taille,
            cible.sha256,
            m.cle_suivante,
            adresse("coeur"),
            adresse("secours"),
            adresse("communaute")
        ))
    })();
    match resultat {
        Ok(record) => chaine_sortante(record),
        Err(e) => chaine_sortante(e),
    }
}

/// Dernière erreur enregistrée par le crate partagé, à libérer.
#[no_mangle]
pub extern "C" fn tordns_derniere_erreur() -> *mut c_char {
    chaine_sortante(tordns_tor::derniere_erreur())
}

/// Libère une chaîne rendue par ce module. Un pointeur nul est ignoré.
#[no_mangle]
pub extern "C" fn tordns_liberer_chaine(pointeur: *mut c_char) {
    if pointeur.is_null() {
        return;
    }
    // SAFETY : le pointeur vient de `CString::into_raw` dans ce module.
    unsafe {
        drop(CString::from_raw(pointeur));
    }
}

/// Libère le tampon d'une réponse. Un tampon nul est ignoré.
#[no_mangle]
pub extern "C" fn tordns_liberer_reponse(r: TordnsReponse) {
    if r.donnees.is_null() || r.longueur == 0 {
        return;
    }
    // SAFETY : le tampon vient de `Vec<u8>` oublié dans ce module.
    unsafe {
        drop(Vec::from_raw_parts(r.donnees, r.longueur, r.longueur));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    const ONION: &CStr = unsafe { CStr::from_bytes_with_nul_unchecked(b"exempleexemple.onion\0") };

    #[test]
    fn pointeur_nul_refuse_sans_panique() {
        let r = tordns_doh(std::ptr::null(), std::ptr::null(), 0, 5000);
        assert_eq!(r.code, CODE_ERREUR);
        assert!(r.donnees.is_null());
        assert_eq!(r.longueur, 0);
        tordns_liberer_reponse(r);

        let message = tordns_demarrer(std::ptr::null(), std::ptr::null());
        assert!(!message.is_null());
        tordns_liberer_chaine(message);
    }

    #[test]
    fn requete_vide_refusee() {
        let r = tordns_doh(ONION.as_ptr(), std::ptr::null(), 0, 5000);
        assert_eq!(r.code, CODE_ERREUR);
        assert!(!tordns_derniere_erreur().is_null());
    }

    #[test]
    fn tor_absent_signale_par_le_code() {
        tordns_arreter();
        assert_eq!(tordns_demarre(), 0);
        let requete = [0x12u8, 0x34, 1, 0];
        let r = tordns_doh(ONION.as_ptr(), requete.as_ptr(), requete.len(), 5000);
        assert_eq!(r.code, CODE_TOR_ABSENT);
        tordns_liberer_reponse(r);
    }

    #[test]
    fn reponse_allouee_puis_liberee() {
        // Même contrat que `reponse` : le Vec est oublié, le tampon rendu à
        // l'appelant, puis libéré par `tordns_liberer_reponse`.
        let mut corps = vec![1u8, 2, 3];
        let r = TordnsReponse {
            donnees: corps.as_mut_ptr(),
            longueur: corps.len(),
            code: CODE_OK,
        };
        std::mem::forget(corps);
        tordns_liberer_reponse(r);
        let vide = TordnsReponse {
            donnees: std::ptr::null_mut(),
            longueur: 0,
            code: CODE_ERREUR,
        };
        tordns_liberer_reponse(vide);
    }

    #[test]
    fn manifeste_vide_ou_invalide_refuse() {
        let message = tordns_verifier_manifeste(std::ptr::null(), 0, std::ptr::null(), 0, 1, 0);
        assert!(!message.is_null());
        let texte = unsafe { CStr::from_ptr(message) }
            .to_str()
            .unwrap()
            .to_owned();
        tordns_liberer_chaine(message);
        assert_eq!(texte, "manifeste vide");

        let brut = b"{}";
        let sig = [0u8; 64];
        let message =
            tordns_verifier_manifeste(brut.as_ptr(), brut.len(), sig.as_ptr(), sig.len(), 1, 0);
        let texte = unsafe { CStr::from_ptr(message) }
            .to_str()
            .unwrap()
            .to_owned();
        tordns_liberer_chaine(message);
        assert!(!texte.is_empty() && texte != "manifeste vide", "{texte}");
    }

    #[test]
    fn chemin_invalide_refuse() {
        let chemin = CString::new("maj/manifeste").unwrap();
        let r = tordns_telecharger(ONION.as_ptr(), chemin.as_ptr(), 1024);
        assert_eq!(r.code, CODE_ERREUR);
        tordns_liberer_reponse(r);
    }
}
