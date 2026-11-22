//! Enregistrement auprès du gestionnaire de services Windows.

use std::ffi::OsString;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

use crate::config::Config;
use crate::wintun::{executer_service, journal};

define_windows_service!(ffi_service_main, service_main);

pub fn demarrer() -> windows_service::Result<()> {
    service_dispatcher::start("TorDNS", ffi_service_main)
}

fn statut(etat: ServiceState) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: etat,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::from_secs(10),
        process_id: None,
    }
}

fn service_main(_arguments: Vec<OsString>) {
    let arret = Arc::new(AtomicBool::new(false));
    let drapeau = Arc::clone(&arret);
    let gestionnaire =
        match service_control_handler::register("TorDNS", move |controle| match controle {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                drapeau.store(true, Ordering::Relaxed);
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        }) {
            Ok(g) => g,
            Err(_) => return,
        };

    let _ = gestionnaire.set_service_status(statut(ServiceState::StartPending));
    let _ = gestionnaire.set_service_status(statut(ServiceState::Running));

    let resultat = Config::charger(&Config::chemin_defaut())
        .and_then(|config| executer_service(&config, Arc::clone(&arret)));

    let code = match resultat {
        Ok(()) => 0,
        Err(e) => {
            journal(&format!("erreur : {e}"));
            1
        }
    };
    let mut final_status = statut(ServiceState::Stopped);
    final_status.exit_code = ServiceExitCode::Win32(code);
    let _ = gestionnaire.set_service_status(final_status);
}
