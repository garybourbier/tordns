//! Cache LRU volatil, horloge injectable pour les tests.

use std::collections::VecDeque;

use crate::dns;

#[derive(Debug, Clone)]
struct Entree {
    reponse: Vec<u8>,
    expire_ms: u64,
    pose_ms: u64,
}

/// Cache borné, du plus ancien (tête) au plus récent (queue).
pub struct Cache {
    taille_max: usize,
    duree_max_ms: u64,
    entrees: VecDeque<(String, Entree)>,
}

impl Cache {
    pub fn new(taille_max: usize, duree_max_ms: u64) -> Self {
        Self {
            taille_max: taille_max.max(1),
            duree_max_ms: duree_max_ms.max(1000),
            entrees: VecDeque::new(),
        }
    }

    pub fn taille(&self) -> usize {
        self.entrees.len()
    }

    pub fn vider(&mut self) {
        self.entrees.clear();
    }

    /// TTL minimal de la section réponse, plafonné par la durée maximale.
    pub fn duree_ms(reponse: &[u8], duree_max_ms: u64) -> u64 {
        let mut min: Option<u32> = None;
        let Ok(fin) = dns::longueur_nom(reponse, 12).map(|l| 12 + l + 4) else {
            return 0;
        };
        let mut p = fin;
        for _ in 0..dns::nombre_reponses(reponse) {
            let Ok(l) = dns::longueur_nom(reponse, p) else {
                return 0;
            };
            p += l;
            if p + 10 > reponse.len() {
                return 0;
            }
            let ttl = u32::from_be_bytes([
                reponse[p + 4],
                reponse[p + 5],
                reponse[p + 6],
                reponse[p + 7],
            ]);
            min = Some(min.map_or(ttl, |m| m.min(ttl)));
            let rdlen = u16::from_be_bytes([reponse[p + 8], reponse[p + 9]]) as usize;
            p += 10 + rdlen;
        }
        match min {
            Some(ttl) => (ttl as u64 * 1000).min(duree_max_ms),
            None => 0,
        }
    }

    /// Sert une réponse avec l'identifiant du client et les TTL vieillis.
    pub fn obtenir(&mut self, cle: &str, id: u16, maintenant_ms: u64) -> Option<Vec<u8>> {
        let position = self.entrees.iter().position(|(k, _)| k == cle)?;
        let (_, e) = self.entrees.remove(position)?;
        if maintenant_ms >= e.expire_ms {
            return None;
        }
        let mut copie = e.reponse.clone();
        dns::ajuster_ttl(&mut copie, (maintenant_ms - e.pose_ms) / 1000);
        let resultat = dns::avec_id(&copie, id);
        self.entrees.push_back((cle.to_string(), e));
        Some(resultat)
    }

    pub fn poser(&mut self, cle: &str, reponse: &[u8], maintenant_ms: u64) {
        if !dns::cacheable(reponse) {
            return;
        }
        let duree = Self::duree_ms(reponse, self.duree_max_ms);
        if duree == 0 {
            return;
        }
        if let Some(position) = self.entrees.iter().position(|(k, _)| k == cle) {
            self.entrees.remove(position);
        }
        if self.entrees.len() >= self.taille_max {
            self.entrees.pop_front();
        }
        self.entrees.push_back((
            cle.to_string(),
            Entree {
                reponse: reponse.to_vec(),
                expire_ms: maintenant_ms + duree,
                pose_ms: maintenant_ms,
            },
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reponse() -> Vec<u8> {
        let mut q = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        q.extend_from_slice(&[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ]);
        q.extend_from_slice(&[0, 1, 0, 1]);
        q.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 1, 0x2c, 0, 4, 1, 2, 3, 4]);
        q
    }

    #[test]
    fn sert_avec_id_et_ttl() {
        let mut c = Cache::new(4, 3_600_000);
        c.poser("k", &reponse(), 0);
        let r = c.obtenir("k", 0x2222, 2000).unwrap();
        assert_eq!(dns::id(&r), 0x2222);
        let p = 12 + 13 + 4 + 2 + 4;
        assert_eq!(&r[p..p + 4], &298u32.to_be_bytes());
    }

    #[test]
    fn expire() {
        let mut c = Cache::new(4, 3_600_000);
        c.poser("k", &reponse(), 0);
        assert!(c.obtenir("k", 1, 300_001).is_none());
        assert_eq!(c.taille(), 0);
    }

    #[test]
    fn ttl_nul_non_cache() {
        let mut r = reponse();
        let p = 12 + 13 + 4 + 2 + 4;
        r[p..p + 4].copy_from_slice(&0u32.to_be_bytes());
        let mut c = Cache::new(4, 3_600_000);
        c.poser("k", &r, 0);
        assert_eq!(c.taille(), 0);
    }

    #[test]
    fn lru_bornee() {
        let mut c = Cache::new(2, 3_600_000);
        for i in 0..5 {
            let mut r = reponse();
            r[1] = i as u8;
            c.poser(&format!("k{i}"), &r, 0);
        }
        assert_eq!(c.taille(), 2);
        assert!(c.obtenir("k0", 0, 1).is_none());
        assert!(c.obtenir("k4", 0, 1).is_some());
    }
}
