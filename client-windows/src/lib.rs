//! Briques du client Windows TorDNS.
//!
//! Les modules `dns`, `cache`, `paquet`, `doh` et `config` sont indépendants de
//! Windows et testables partout. `wintun` et `service` ne sont compilés que
//! pour Windows.

pub mod cache;
pub mod config;
pub mod dns;
pub mod doh;
pub mod paquet;
pub mod resolveur;

#[cfg(windows)]
pub mod service;
#[cfg(windows)]
pub mod wintun;

/// Version affichée par `--version`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
