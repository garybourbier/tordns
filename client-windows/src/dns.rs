//! Format DNS wire : lecture des noms compressés, clé de cache, TTL, SERVFAIL.

/// Une question DNS unique (QDCOUNT = 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub nom: String,
    pub qtype: u16,
    pub qclass: u16,
    pub dnssec: bool,
    /// Position juste après la question.
    pub fin: usize,
}

fn erreur(message: &str) -> String {
    message.to_string()
}

/// Longueur du nom à `offset`, pointeurs de compression compris.
pub fn longueur_nom(m: &[u8], offset: usize) -> Result<usize, String> {
    let mut i = offset;
    loop {
        let l = *m.get(i).ok_or_else(|| erreur("nom tronqué"))? as usize;
        if l == 0 {
            return Ok(i - offset + 1);
        }
        if l & 0xc0 == 0xc0 {
            if i + 1 >= m.len() {
                return Err(erreur("pointeur tronqué"));
            }
            return Ok(i - offset + 2);
        }
        if l & 0xc0 != 0 {
            return Err(erreur("label invalide"));
        }
        i += l + 1;
        if i > m.len() {
            return Err(erreur("nom tronqué"));
        }
    }
}

/// Lit un nom (suit la compression, bornée) et le normalise en minuscules.
pub fn lire_nom(m: &[u8], offset: usize) -> Result<String, String> {
    let mut sortie = String::new();
    let mut i = offset;
    let mut sauts = 0;
    loop {
        let l = *m.get(i).ok_or_else(|| erreur("nom tronqué"))? as usize;
        if l == 0 {
            break;
        }
        if l & 0xc0 == 0xc0 {
            sauts += 1;
            if sauts > 16 {
                return Err(erreur("compression invalide"));
            }
            let bas = *m.get(i + 1).ok_or_else(|| erreur("pointeur tronqué"))? as usize;
            i = ((l & 0x3f) << 8) | bas;
            continue;
        }
        if l & 0xc0 != 0 || i + 1 + l > m.len() {
            return Err(erreur("label invalide"));
        }
        if !sortie.is_empty() {
            sortie.push('.');
        }
        let partie =
            std::str::from_utf8(&m[i + 1..i + 1 + l]).map_err(|_| erreur("label non UTF-8"))?;
        sortie.push_str(&partie.to_ascii_lowercase());
        i += l + 1;
    }
    Ok(sortie)
}

fn u16be(m: &[u8], p: usize) -> Result<u16, String> {
    Ok(
        ((*m.get(p).ok_or_else(|| erreur("champ tronqué"))? as u16) << 8)
            | *m.get(p + 1).ok_or_else(|| erreur("champ tronqué"))? as u16,
    )
}

fn u32be(m: &[u8], p: usize) -> Result<u32, String> {
    Ok((u16be(m, p)? as u32) << 16 | u16be(m, p + 2)? as u32)
}

/// Analyse une requête : une seule question, nom, type, classe, bit DO.
pub fn analyser(m: &[u8]) -> Result<Question, String> {
    if m.len() < 12 {
        return Err(erreur("en-tête tronqué"));
    }
    if u16be(m, 4)? != 1 {
        return Err(erreur("une seule question attendue"));
    }
    let fin = 12 + longueur_nom(m, 12)?;
    if fin + 4 > m.len() {
        return Err(erreur("question tronquée"));
    }
    let nom = lire_nom(m, 12)?;
    let qtype = u16be(m, fin)?;
    let qclass = u16be(m, fin + 2)?;
    Ok(Question {
        nom,
        qtype,
        qclass,
        dnssec: dnssec(m, fin + 4)?,
        fin: fin + 4,
    })
}

/// Bit DO de l'OPT, s'il est présent dans la section additionnelle.
fn dnssec(m: &[u8], mut p: usize) -> Result<bool, String> {
    let an = u16be(m, 6)? as usize;
    let ns = u16be(m, 8)? as usize;
    let ar = u16be(m, 10)? as usize;
    for _ in 0..an + ns {
        p += longueur_nom(m, p)?;
        if p + 10 > m.len() {
            return Err(erreur("enregistrement tronqué"));
        }
        let rdlen = u16be(m, p + 8)? as usize;
        p += 10 + rdlen;
    }
    for _ in 0..ar {
        p += longueur_nom(m, p)?;
        if p + 10 > m.len() {
            return Err(erreur("additionnel tronqué"));
        }
        let t = u16be(m, p)?;
        let rdlen = u16be(m, p + 8)? as usize;
        if t == 41 {
            // TTL de l'OPT : ext-rcode(1), version(1), drapeaux(2) ; DO = 0x8000.
            return Ok(p + 6 < m.len() && m[p + 6] & 0x80 != 0);
        }
        p += 10 + rdlen;
    }
    Ok(false)
}

/// Clé de cache : nom normalisé + type + classe + bit DO.
pub fn cle(q: &Question) -> String {
    format!(
        "{}|{}|{}|{}",
        q.nom,
        q.qtype,
        q.qclass,
        if q.dnssec { "do" } else { "plain" }
    )
}

pub fn id(m: &[u8]) -> u16 {
    ((m[0] as u16) << 8) | m[1] as u16
}

pub fn avec_id(reponse: &[u8], id: u16) -> Vec<u8> {
    let mut r = reponse.to_vec();
    if r.len() >= 2 {
        r[0] = (id >> 8) as u8;
        r[1] = id as u8;
    }
    r
}

pub fn rcode(m: &[u8]) -> i32 {
    if m.len() > 3 {
        (m[3] & 0x0f) as i32
    } else {
        -1
    }
}

pub fn tronquee(m: &[u8]) -> bool {
    m.len() > 2 && m[2] & 0x02 != 0
}

/// NOERROR et NXDOMAIN sont admissibles ; le TTL décidera si la réponse
/// négative porte un SOA exploitable.
pub fn cacheable(m: &[u8]) -> bool {
    m.len() >= 12 && matches!(rcode(m), 0 | 3) && !tronquee(m)
}

pub fn nombre_reponses(m: &[u8]) -> usize {
    if m.len() >= 8 {
        (((m[6] as usize) << 8) | m[7] as usize) as usize
    } else {
        0
    }
}

pub fn nombre_autorites(m: &[u8]) -> usize {
    if m.len() >= 10 {
        (((m[8] as usize) << 8) | m[9] as usize) as usize
    } else {
        0
    }
}

/// Lit un RR à `p` : type, TTL, début des données, position suivante.
fn rr(m: &[u8], p: usize) -> Result<(u16, u32, usize, usize), String> {
    let l = longueur_nom(m, p)?;
    let q = p + l;
    if q + 10 > m.len() {
        return Err(erreur("enregistrement tronqué"));
    }
    let typ = u16be(m, q)?;
    let ttl = u32be(m, q + 4)?;
    let rdlen = u16be(m, q + 8)? as usize;
    let debut = q + 10;
    let fin = debut + rdlen;
    if fin > m.len() {
        return Err(erreur("données tronquées"));
    }
    Ok((typ, ttl, debut, fin))
}

/// Plus petit TTL de la section réponse ; `None` si elle est vide ou illisible.
pub fn ttl_reponse(m: &[u8]) -> Option<u32> {
    let mut p = 12 + longueur_nom(m, 12).ok()? + 4;
    let mut min = None;
    for _ in 0..nombre_reponses(m) {
        let (_, ttl, _, fin) = rr(m, p).ok()?;
        min = Some(min.map_or(ttl, |v: u32| v.min(ttl)));
        p = fin;
    }
    min
}

/// TTL négatif RFC 2308 : minimum du TTL du SOA et de son champ MINIMUM.
pub fn ttl_negatif(m: &[u8]) -> Option<u32> {
    let mut p = 12 + longueur_nom(m, 12).ok()? + 4;
    for _ in 0..nombre_reponses(m) {
        let (_, _, _, fin) = rr(m, p).ok()?;
        p = fin;
    }
    let mut min = None;
    for _ in 0..nombre_autorites(m) {
        let (typ, ttl, debut, fin) = rr(m, p).ok()?;
        if typ == 6 {
            if fin - debut < 4 {
                return None;
            }
            let minimum = u32be(m, fin - 4).ok()?;
            let valeur = ttl.min(minimum);
            min = Some(min.map_or(valeur, |v: u32| v.min(valeur)));
        }
        p = fin;
    }
    min
}

/// Durée de cache en millisecondes : réponse seule pour une réponse positive,
/// SOA pour une réponse négative, plancher 1 s et plafond fourni.
pub fn duree_cache(m: &[u8], duree_max_ms: u64) -> u64 {
    if !cacheable(m) {
        return 0;
    }
    let ttl = if rcode(m) == 0 && nombre_reponses(m) > 0 {
        ttl_reponse(m)
    } else {
        ttl_negatif(m)
    };
    match ttl {
        Some(0) | None => 0,
        Some(t) => (t as u64 * 1000).clamp(1000, duree_max_ms.max(1000)),
    }
}

/// Décrémente les TTL des sections réponse et autorité (plancher 1 s).
pub fn ajuster_ttl(m: &mut [u8], ecart: u64) {
    if ecart == 0 {
        return;
    }
    let Ok(fin) = longueur_nom(m, 12).map(|l| 12 + l + 4) else {
        return;
    };
    let mut p = fin;
    for _ in 0..nombre_reponses(m) + nombre_autorites(m) {
        let Ok(l) = longueur_nom(m, p) else { return };
        p += l;
        if p + 10 > m.len() {
            return;
        }
        let Some(ttl) = u32be(m, p + 4).ok() else {
            return;
        };
        let reste = (ttl as u64).saturating_sub(ecart).max(1) as u32;
        m[p + 4..p + 8].copy_from_slice(&reste.to_be_bytes());
        let Some(rdlen) = u16be(m, p + 8).ok() else {
            return;
        };
        p += 10 + rdlen as usize;
    }
}

/// Construit une réponse SERVFAIL minimale reprenant l'identifiant et la question.
pub fn servfail(requete: &[u8]) -> Vec<u8> {
    if requete.len() < 12 {
        return Vec::new();
    }
    let Ok(longueur_question) = longueur_nom(requete, 12) else {
        return Vec::new();
    };
    let fin = 12 + longueur_question + 4;
    if fin > requete.len() {
        return Vec::new();
    }
    let mut r = vec![0u8; requete.len().min(512)];
    r[0] = requete[0];
    r[1] = requete[1];
    r[2] = 0x81;
    r[3] = 0x82;
    r[5] = 1;
    let fin = fin.min(r.len());
    r[12..fin].copy_from_slice(&requete[12..fin]);
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    fn requete(nom: &str, id: u16, dnssec: bool) -> Vec<u8> {
        let mut q = vec![
            (id >> 8) as u8,
            id as u8,
            0x01,
            0x00,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        for partie in nom.split('.') {
            q.push(partie.len() as u8);
            q.extend_from_slice(partie.as_bytes());
        }
        q.extend_from_slice(&[0, 0, 1, 0, 1]);
        if dnssec {
            q[11] = 1;
            q.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0x80, 0, 0, 0]);
        }
        q
    }

    fn reponse_positive(q: &[u8]) -> Vec<u8> {
        let fin = 12 + longueur_nom(q, 12).unwrap() + 4;
        let mut r = vec![q[0], q[1], 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        r.extend_from_slice(&q[12..fin]);
        r.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 1, 0x2c, 0, 4, 93, 184, 216, 34]);
        r
    }

    #[test]
    fn nom_et_cle() {
        let q = analyser(&requete("Example.COM", 0x1234, false)).unwrap();
        assert_eq!(q.nom, "example.com");
        assert_eq!(cle(&q), "example.com|1|1|plain");
        assert!(!q.dnssec);
        assert_eq!(id(&requete("a.fr", 7, false)), 7);
    }

    #[test]
    fn do_detecte() {
        let q = analyser(&requete("example.com", 1, true)).unwrap();
        assert!(q.dnssec);
        assert_eq!(cle(&q), "example.com|1|1|do");
    }

    #[test]
    fn compression_lue() {
        let mut m = requete("example.com", 1, false);
        m.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 0]);
        assert_eq!(lire_nom(&m, m.len() - 12).unwrap(), "example.com");
    }

    #[test]
    fn ttl_decremente_et_plancher() {
        let q = requete("example.com", 1, false);
        let mut r = reponse_positive(&q);
        let p = DnsPos::ttl(&r);
        assert_eq!(u32be(&r, p).unwrap(), 300);
        ajuster_ttl(&mut r, 2);
        assert_eq!(u32be(&r, p).unwrap(), 298);
        ajuster_ttl(&mut r, 10_000);
        assert_eq!(u32be(&r, p).unwrap(), 1);
    }

    struct DnsPos;
    impl DnsPos {
        fn ttl(m: &[u8]) -> usize {
            let fin = 12 + longueur_nom(m, 12).unwrap() + 4;
            fin + longueur_nom(m, fin).unwrap() + 4
        }
    }

    #[test]
    fn servfail_bien_forme() {
        let q = requete("example.com", 0x4242, false);
        let r = servfail(&q);
        assert_eq!(rcode(&r), 2);
        assert_eq!(id(&r), 0x4242);
        assert_eq!(r[2] & 0x80, 0x80);
        assert_eq!(r[3] & 0x80, 0x80);
        assert_eq!(analyser(&r).unwrap().nom, "example.com");
    }

    fn soa(ttl: u32, minimum: u32) -> Vec<u8> {
        let mut r = vec![0xc0, 12, 0, 6, 0, 1];
        r.extend_from_slice(&ttl.to_be_bytes());
        r.extend_from_slice(&24u16.to_be_bytes());
        r.extend_from_slice(&[0, 0, 0, 0]);
        for _ in 0..4 {
            r.extend_from_slice(&3600u32.to_be_bytes());
        }
        r.extend_from_slice(&minimum.to_be_bytes());
        r
    }

    fn negative(rcode: u8, avec_soa: bool) -> Vec<u8> {
        let q = requete("absent.example", 7, false);
        let mut r = vec![0, 7, 0x81, 0x80 | rcode, 0, 1, 0, 0, 0, 0, 0, 0];
        let fin = 12 + longueur_nom(&q, 12).unwrap() + 4;
        r.extend_from_slice(&q[12..fin]);
        if avec_soa {
            r[8] = 0;
            r[9] = 1;
            r.extend_from_slice(&soa(600, 60));
        }
        r
    }

    #[test]
    fn ttl_negatif_suit_le_soa() {
        assert_eq!(ttl_negatif(&negative(3, true)), Some(60));
        assert_eq!(ttl_negatif(&negative(0, true)), Some(60));
        assert_eq!(ttl_negatif(&negative(3, false)), None);
        assert!(cacheable(&negative(3, true)));
    }

    #[test]
    fn ttl_reponse_ignore_autorite() {
        let q = requete("example.com", 1, false);
        let mut r = reponse_positive(&q);
        r[9] = 1; // une autorité, avec un TTL bien plus court
        r.extend_from_slice(&soa(30, 10));
        assert_eq!(ttl_reponse(&r), Some(300));
    }

    #[test]
    fn duree_cache_plafonne_et_ignore_ttl_nul() {
        let q = requete("example.com", 1, false);
        let r = reponse_positive(&q);
        assert_eq!(duree_cache(&r, 3_600_000), 300_000);
        assert_eq!(duree_cache(&r, 10_000), 10_000);
        let mut nul = r.clone();
        let fin = 12 + longueur_nom(&nul, 12).unwrap() + 4;
        let p = fin + longueur_nom(&nul, fin).unwrap() + 4;
        nul[p..p + 4].copy_from_slice(&0u32.to_be_bytes());
        assert_eq!(duree_cache(&nul, 3_600_000), 0);
        assert_eq!(duree_cache(&negative(3, true), 3_600_000), 60_000);
    }

    #[test]
    fn cacheable_refuse_erreurs() {
        let q = requete("example.com", 1, false);
        assert!(cacheable(&reponse_positive(&q)));
        let mut sf = servfail(&q);
        sf[3] = 0x82;
        assert!(!cacheable(&sf));
        let mut tronquee = reponse_positive(&q);
        tronquee[2] |= 0x02;
        assert!(!cacheable(&tronquee));
    }
}
