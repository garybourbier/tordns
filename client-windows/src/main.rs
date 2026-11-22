//! Client Windows TorDNS.
//!
//! Sans argument, le binaire s'enregistre auprès du gestionnaire de services.
//! `--console` exécute le relais au premier plan (débogage), `--verifier-config`
//! contrôle un fichier sans toucher au réseau, `--aide` affiche l'usage.

use std::path::PathBuf;

use tordns_win::config::Config;

fn aide() {
    println!(
        "TorDNS client Windows {version}\n\
\n\
Usage :\n\
  tordns-client                         démarre en tant que service Windows\n\
  tordns-client --console [fichier]     relais au premier plan\n\
  tordns-client --verifier-config <f>   valide la configuration sans réseau\n\
  tordns-client --aide | --version\n\
\n\
Configuration par défaut : %ProgramData%\\TorDNS\\client.conf\n\
  onion = <adresse>.onion\n\
  socks = 127.0.0.1:9050\n\
  tun = TorDNS\n\
  cache = 4096\n\
  anti_fuite = non\n\
  ttl_max = 3600\n\
  delai = 15\n\
\n\
WinTun : wintun.dll doit être présente à côté de l'exécutable ou dans\n\
System32. Le service exige les droits administrateur.",
        version = tordns_win::VERSION
    );
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--aide") | Some("--help") | Some("-h") => aide(),
        Some("--version") | Some("-V") => println!("tordns-client {}", tordns_win::VERSION),
        Some("--verifier-config") => {
            let Some(chemin) = args.get(1) else {
                eprintln!("erreur : chemin de configuration attendu");
                std::process::exit(2);
            };
            match Config::charger(&PathBuf::from(chemin)) {
                Ok(c) => {
                    println!(
                        "configuration valide : tunnel={}, socks={}, cache={}, anti_fuite={}",
                        c.tun, c.socks, c.cache, c.anti_fuite
                    );
                }
                Err(e) => {
                    eprintln!("configuration invalide : {e}");
                    std::process::exit(1);
                }
            }
        }
        Some("--console") => {
            let chemin = args
                .get(1)
                .map(PathBuf::from)
                .unwrap_or_else(Config::chemin_defaut);
            let config = match Config::charger(&chemin) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("erreur de configuration : {e}");
                    std::process::exit(1);
                }
            };
            #[cfg(windows)]
            if let Err(e) = tordns_win::wintun::executer_service(
                &config,
                std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            ) {
                eprintln!("erreur : {e}");
                std::process::exit(1);
            }
            #[cfg(not(windows))]
            {
                let _ = config;
                eprintln!("le mode console avec WinTun n'est disponible que sous Windows");
                std::process::exit(1);
            }
        }
        Some(autre) => {
            eprintln!("option inconnue : {autre}\n");
            aide();
            std::process::exit(2);
        }
        None => {
            #[cfg(windows)]
            if let Err(e) = tordns_win::service::demarrer() {
                eprintln!(
                    "impossible de démarrer le service TorDNS : {e}\n\
                     Utilisez « sc start TorDNS » une fois le service installé, \
                     ou --console pour un test manuel."
                );
                std::process::exit(1);
            }
            #[cfg(not(windows))]
            {
                eprintln!("ce binaire doit être compilé pour Windows (x86_64-pc-windows-gnu)");
                std::process::exit(1);
            }
        }
    }
}
