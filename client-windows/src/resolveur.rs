//! Cœur du relais : cache d'abord, DoH ensuite, SERVFAIL en dernier recours.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::cache::Cache;
use crate::config::Config;
use crate::dns;
use crate::doh::ClientDoh;

#[derive(Default)]
pub struct Stats {
    pub total: AtomicU64,
    pub hits: AtomicU64,
    pub erreurs: AtomicU64,
}

impl Stats {
    pub fn instantane(&self) -> (u64, u64, u64) {
        (
            self.total.load(Ordering::Relaxed),
            self.hits.load(Ordering::Relaxed),
            self.erreurs.load(Ordering::Relaxed),
        )
    }
}

pub struct Resolveur {
    cache: Mutex<Cache>,
    doh: ClientDoh,
    pub stats: Stats,
    pub onion: String,
    dnssec: bool,
}

impl Resolveur {
    pub fn depuis_config(c: &Config) -> Result<Self, String> {
        let onion = crate::adresses::adresse_effective(c);
        Ok(Self {
            cache: Mutex::new(Cache::new(c.cache, c.ttl_max_s.saturating_mul(1000))),
            doh: ClientDoh::new(&c.socks, &onion, Duration::from_secs(c.delai_s.max(1)))?,
            stats: Stats::default(),
            onion,
            dnssec: c.dnssec,
        })
    }

    fn maintenant_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    /// Bloquant : renvoie toujours un message DNS exploitable.
    pub fn resoudre(&self, requete: &[u8]) -> Vec<u8> {
        self.stats.total.fetch_add(1, Ordering::Relaxed);
        let Ok(question) = dns::analyser(requete) else {
            self.stats.erreurs.fetch_add(1, Ordering::Relaxed);
            return dns::servfail(requete);
        };
        let cle = dns::cle(&question);
        let id = dns::id(requete);

        if let Ok(mut cache) = self.cache.lock() {
            if let Some(copie) = cache.obtenir(&cle, id, Self::maintenant_ms()) {
                self.stats.hits.fetch_add(1, Ordering::Relaxed);
                return copie;
            }
        }

        let resultat = if self.dnssec {
            crate::dnssec::resoudre(&self.doh, requete)
        } else {
            self.doh.poster(requete).map_err(|e| e.to_string())
        };
        match resultat {
            Ok(reponse) if reponse.len() >= 12 && reponse[2] & 0x80 != 0 => {
                if let Ok(mut cache) = self.cache.lock() {
                    cache.poser(&cle, &reponse, Self::maintenant_ms());
                }
                dns::avec_id(&reponse, id)
            }
            _ => {
                self.stats.erreurs.fetch_add(1, Ordering::Relaxed);
                dns::servfail(requete)
            }
        }
    }

    pub fn taille_cache(&self) -> usize {
        self.cache.lock().map(|c| c.taille()).unwrap_or(0)
    }

    pub fn vider_cache(&self) {
        if let Ok(mut c) = self.cache.lock() {
            c.vider();
        }
    }
}
