//! Chargement dynamique de WinTun, configuration de l'adaptateur et boucle DNS.
//!
//! WinTun est un pilote signé fourni séparément (wintun.dll) : il n'est pas
//! embarqué dans le dépôt. Les fonctions sont résolues à l'exécution pour que
//! le binaire démarre et affiche une erreur claire si la DLL manque.

use std::ffi::{c_void, CString};
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread;

use crate::config::Config;
use crate::paquet;
use crate::resolveur::Resolveur;

type Handle = *mut c_void;
type Adapter = *mut c_void;
type Session = *mut c_void;

#[repr(C)]
struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

const ERREUR_PLUS_D_ITEMS: u32 = 259;

#[link(name = "kernel32")]
extern "system" {
    fn LoadLibraryW(nom: *const u16) -> Handle;
    fn GetProcAddress(module: Handle, nom: *const u8) -> *mut c_void;
    fn FreeLibrary(module: Handle) -> i32;
    fn GetLastError() -> u32;
    fn WaitForSingleObject(objet: Handle, delai_ms: u32) -> u32;
}

type FnCreateAdapter = unsafe extern "system" fn(*const u16, *const u16, *const Guid) -> Adapter;
type FnOpenAdapter = unsafe extern "system" fn(*const u16, *const u16) -> Adapter;
type FnCloseAdapter = unsafe extern "system" fn(Adapter);
type FnDeleteAdapter = unsafe extern "system" fn(Adapter) -> i32;
type FnStartSession = unsafe extern "system" fn(Adapter, u32) -> Session;
type FnEndSession = unsafe extern "system" fn(Session);
type FnReceivePacket = unsafe extern "system" fn(Session, *mut u32) -> *mut u8;
type FnReleasePacket = unsafe extern "system" fn(Session, *const u8);
type FnAllocatePacket = unsafe extern "system" fn(Session, u32) -> *mut u8;
type FnSendPacket = unsafe extern "system" fn(Session, *const u8);
type FnReadWaitEvent = unsafe extern "system" fn(Session) -> Handle;

struct Api {
    module: Handle,
    create: FnCreateAdapter,
    open: Option<FnOpenAdapter>,
    close: FnCloseAdapter,
    delete: Option<FnDeleteAdapter>,
    start: FnStartSession,
    end: FnEndSession,
    receive: FnReceivePacket,
    release: FnReleasePacket,
    allocate: FnAllocatePacket,
    send: FnSendPacket,
    read_wait: FnReadWaitEvent,
}

// Les pointeurs WinTun sont opaques et toutes les fonctions sont thread-safe
// pour l'envoi ; l'API reste valide pendant toute la vie du service.
unsafe impl Send for Api {}
unsafe impl Sync for Api {}

impl Api {
    fn charger(dossier_exe: &PathBuf) -> Result<&'static Api, String> {
        static API: OnceLock<Api> = OnceLock::new();
        if let Some(api) = API.get() {
            return Ok(api);
        }
        let mut module: Handle = ptr::null_mut();
        for candidat in [
            dossier_exe.join("wintun.dll"),
            PathBuf::from(r"C:\Windows\System32\wintun.dll"),
        ] {
            let large: Vec<u16> = candidat
                .as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            /* SAFETY: chaîne UTF-16 terminée par zéro, allouée pour l'appel. */
            let h = unsafe { LoadLibraryW(large.as_ptr()) };
            if !h.is_null() {
                module = h;
                break;
            }
        }
        if module.is_null() {
            return Err(
                "wintun.dll introuvable (placez-la à côté de l'exécutable ou dans System32)".into(),
            );
        }

        macro_rules! fonction {
            ($nom:literal, $type:ty) => {{
                let c = CString::new($nom).unwrap();
                /* SAFETY: nom de symbole valide, module chargé. */
                let p = unsafe { GetProcAddress(module, c.as_ptr() as *const u8) };
                if p.is_null() {
                    /* SAFETY: module chargé par LoadLibraryW. */
                    unsafe { FreeLibrary(module) };
                    return Err(format!("symbole WinTun manquant : {}", $nom));
                }
                unsafe { std::mem::transmute::<*mut c_void, $type>(p) }
            }};
        }

        let api = Api {
            module,
            create: fonction!("WintunCreateAdapter", FnCreateAdapter),
            open: {
                let c = CString::new("WintunOpenAdapter").unwrap();
                /* SAFETY: symbole optionnel. */
                let p = unsafe { GetProcAddress(module, c.as_ptr() as *const u8) };
                if p.is_null() {
                    None
                } else {
                    Some(unsafe { std::mem::transmute::<*mut c_void, FnOpenAdapter>(p) })
                }
            },
            close: fonction!("WintunCloseAdapter", FnCloseAdapter),
            delete: {
                let c = CString::new("WintunDeleteAdapter").unwrap();
                /* SAFETY: symbole optionnel. */
                let p = unsafe { GetProcAddress(module, c.as_ptr() as *const u8) };
                if p.is_null() {
                    None
                } else {
                    Some(unsafe { std::mem::transmute::<*mut c_void, FnDeleteAdapter>(p) })
                }
            },
            start: fonction!("WintunStartSession", FnStartSession),
            end: fonction!("WintunEndSession", FnEndSession),
            receive: fonction!("WintunReceivePacket", FnReceivePacket),
            release: fonction!("WintunReleaseReceivePacket", FnReleasePacket),
            allocate: fonction!("WintunAllocateSendPacket", FnAllocatePacket),
            send: fonction!("WintunSendPacket", FnSendPacket),
            read_wait: fonction!("WintunGetReadWaitEvent", FnReadWaitEvent),
        };
        Ok(API.get_or_init(|| api))
    }
}

/// Session partagée entre le lecteur et les travailleurs DoH.
struct SessionPartagee {
    api: &'static Api,
    session: Session,
}

// SAFETY: WintunSendPacket est documenté comme sûr depuis plusieurs threads ;
// la session n'est fermée qu'après l'arrêt de tous les travailleurs.
unsafe impl Send for SessionPartagee {}
unsafe impl Sync for SessionPartagee {}

impl SessionPartagee {
    fn envoyer(&self, paquet: &[u8]) -> Result<(), String> {
        if paquet.is_empty() {
            return Ok(());
        }
        /* SAFETY: allocation WinTun puis copie dans le tampon fourni. */
        let tampon = unsafe { (self.api.allocate)(self.session, paquet.len() as u32) };
        if tampon.is_null() {
            return Err("WinTun : allocation du paquet impossible".into());
        }
        /* SAFETY: tampon de taille demandée, source valide. */
        unsafe {
            ptr::copy_nonoverlapping(paquet.as_ptr(), tampon, paquet.len());
            (self.api.send)(self.session, tampon);
        }
        Ok(())
    }
}

fn large(texte: &str) -> Vec<u16> {
    std::ffi::OsStr::new(texte)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn executer(programme: &str, args: &[&str]) -> Result<(), String> {
    let sortie = std::process::Command::new(programme)
        .args(args)
        .output()
        .map_err(|e| format!("lancement de {programme} : {e}"))?;
    if !sortie.status.success() {
        return Err(format!(
            "{programme} a échoué : {}",
            String::from_utf8_lossy(&sortie.stderr).trim()
        ));
    }
    Ok(())
}

fn configurer_adaptateur(nom: &str, anti_fuite: bool) -> Result<(), String> {
    executer(
        "netsh",
        &[
            "interface",
            "ipv4",
            "set",
            "address",
            &format!("name={nom}"),
            "source=static",
            "address=10.111.222.2",
            "mask=255.255.255.255",
            "gateway=none",
        ],
    )?;
    executer(
        "netsh",
        &[
            "interface",
            "ipv4",
            "set",
            "dnsservers",
            &format!("name={nom}"),
            "source=static",
            "address=10.111.222.1",
            "register=none",
            "validate=no",
        ],
    )?;
    executer(
        "netsh",
        &[
            "interface",
            "ipv4",
            "add",
            "route",
            "prefix=10.111.222.1/32",
            &format!("interface={nom}"),
            "metric=1",
            "store=active",
        ],
    )?;
    if anti_fuite {
        // Empêche Windows d'envoyer la même question à tous les résolveurs de
        // toutes les interfaces, ce qui fuiterait en clair.
        for (cle, valeur) in [
            ("DisableSmartNameResolution", "1"),
            ("DisableSmartMultiHomedNameResolution", "1"),
        ] {
            executer(
                "reg",
                &[
                    "add",
                    r"HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters",
                    "/v",
                    cle,
                    "/t",
                    "REG_DWORD",
                    "/d",
                    valeur,
                    "/f",
                ],
            )?;
        }
    }
    Ok(())
}

/// Crée l'adaptateur, configure Windows puis traite le DNS jusqu'à l'arrêt.
pub fn executer_service(config: &Config, arret: Arc<AtomicBool>) -> Result<(), String> {
    let dossier = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));
    let api = Api::charger(&dossier)?;

    let nom = large(&config.tun);
    let type_tunnel = large("TorDNS");
    /* SAFETY: chaînes valides, GUID nul accepté par WinTun. */
    let mut adaptateur = unsafe { (api.create)(nom.as_ptr(), type_tunnel.as_ptr(), ptr::null()) };
    if adaptateur.is_null() {
        let code = unsafe { GetLastError() };
        // 183 = ERROR_ALREADY_EXISTS : un arrêt brutal a laissé l'adaptateur.
        if code == 183 {
            if let Some(ouvrir) = api.open {
                adaptateur = unsafe { ouvrir(type_tunnel.as_ptr(), nom.as_ptr()) };
            }
        }
        if adaptateur.is_null() {
            return Err(format!(
                "WintunCreateAdapter a échoué (code {code}) : le service doit tourner en administrateur"
            ));
        }
        journal("adaptateur WinTun existant réutilisé");
    }

    let resultat = (|| {
        configurer_adaptateur(&config.tun, config.anti_fuite)?;
        /* SAFETY: adaptateur valide jusqu'à la fermeture. */
        let session = unsafe { (api.start)(adaptateur, 0x40_0000) };
        if session.is_null() {
            return Err("WintunStartSession a échoué".into());
        }
        let partagee = Arc::new(SessionPartagee { api, session });
        let resolveur = Arc::new(Resolveur::depuis_config(config)?);
        let total = Arc::new(AtomicU64::new(0));
        // File entre le lecteur et les travailleurs DoH.
        let (tx, rx) = std::sync::mpsc::channel::<(Vec<u8>, paquet::Requete)>();
        let rx = Arc::new(std::sync::Mutex::new(rx));
        let mut travailleurs = Vec::new();
        for _ in 0..8 {
            let s = Arc::clone(&partagee);
            let r = Arc::clone(&resolveur);
            let rx = Arc::clone(&rx);
            travailleurs.push(thread::spawn(move || loop {
                let tache = match rx.lock() {
                    Ok(g) => g.recv(),
                    Err(_) => break,
                };
                let Ok((brut, requete)) = tache else { break };
                let reponse = r.resoudre(&requete.dns);
                if reponse.is_empty() {
                    continue;
                }
                let sortant = paquet::reponse(&brut, &requete, &reponse);
                if let Err(e) = s.envoyer(&sortant) {
                    journal(&format!("envoi WinTun : {e}"));
                }
            }));
        }

        journal("relais DNS démarré sur l'adaptateur WinTun");
        /* SAFETY: événement de lecture valide tant que la session vit. */
        let evenement = unsafe { (api.read_wait)(session) };
        while !arret.load(Ordering::Relaxed) {
            let attendu = unsafe { WaitForSingleObject(evenement, 500) };
            if attendu != 0 {
                // WAIT_TIMEOUT : on revérifie le drapeau d'arrêt.
                continue;
            }
            loop {
                let mut taille = 0u32;
                /* SAFETY: session valide, taille écrite par WinTun. */
                let tampon = unsafe { (api.receive)(session, &mut taille) };
                if tampon.is_null() {
                    let code = unsafe { GetLastError() };
                    if code == ERREUR_PLUS_D_ITEMS {
                        break;
                    }
                    thread::sleep(std::time::Duration::from_millis(10));
                    break;
                }
                let brut = unsafe { std::slice::from_raw_parts(tampon, taille as usize) }.to_vec();
                let requete = paquet::extraire(&brut);
                unsafe { (api.release)(session, tampon) };
                if let Some(q) = requete {
                    total.fetch_add(1, Ordering::Relaxed);
                    if tx.send((brut, q)).is_err() {
                        break;
                    }
                }
            }
        }
        drop(tx);
        for t in travailleurs {
            let _ = t.join();
        }
        unsafe { (api.end)(session) };
        let (requetes, _, _) = resolveur.stats.instantane();
        journal(&format!("arrêt : {requetes} requêtes, 0 nom journalisé"));
        Ok(())
    })();

    /* SAFETY: adaptateur créé plus haut. La suppression retire aussi les
    routes et le DNS configurés ; à défaut, on ferme le handle. */
    match api.delete {
        Some(supprimer) => {
            if unsafe { supprimer(adaptateur) } == 0 {
                unsafe { FreeLibrary(api.module) };
            }
        }
        None => unsafe { (api.close)(adaptateur) },
    }
    if resultat.is_err() {
        unsafe { FreeLibrary(api.module) };
    }
    resultat
}

/// Petit journal sans nom de domaine, sur la sortie d'erreur.
pub fn journal(message: &str) {
    eprintln!("tordns: {message}");
}
