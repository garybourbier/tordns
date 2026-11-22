//! Briques du client Windows TorDNS.
//!
//! Les modules `dns`, `cache`, `paquet`, `doh` et `config` sont indépendants de
//! Windows et testables partout. `wintun` et `service` ne sont compilés que
//! pour Windows.

pub mod cache;
pub mod config;
pub mod diagnostic;
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

#[cfg(test)]
mod tests_hostiles {
    fn suivant(etat: &mut u64) -> u64 {
        *etat = etat
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        *etat >> 33
    }

    #[test]
    fn dix_mille_paquets_dns_hostiles() {
        let mut etat = 13u64;
        for _ in 0..10_000 {
            let longueur = (suivant(&mut etat) % 600) as usize;
            let mut msg = vec![0u8; longueur];
            for octet in &mut msg {
                *octet = suivant(&mut etat) as u8;
            }
            let _ = crate::dns::analyser(&msg);
            let _ = crate::dns::cacheable(&msg);
            let _ = crate::dns::ttl_reponse(&msg);
            let _ = crate::dns::ttl_negatif(&msg);
            let _ = crate::dns::duree_cache(&msg, 3_600_000);
            let _ = crate::dns::avec_id(&msg, 7);
            let _ = crate::dns::servfail(&msg);
            let _ = crate::paquet::extraire(&msg);
        }
    }
}
