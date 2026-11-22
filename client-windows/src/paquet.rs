//! Paquets IPv4/UDP : extraction du DNS et réinjection de la réponse.

/// Vue sur une requête DNS transportée en UDP vers le port 53.
#[derive(Debug, Clone)]
pub struct Requete {
    pub ihl: usize,
    pub port_source: u16,
    pub port_destination: u16,
    pub dns: Vec<u8>,
}

/// Renvoie la requête si le paquet est un IPv4/UDP vers le port 53.
pub fn extraire(p: &[u8]) -> Option<Requete> {
    if p.len() < 28 || p[0] >> 4 != 4 {
        return None;
    }
    let ihl = (p[0] as usize & 0x0f) * 4;
    if ihl < 20 || p.len() < ihl + 8 || p[9] != 17 {
        return None;
    }
    let total = u16::from_be_bytes([p[2], p[3]]) as usize;
    if total < ihl + 8 || total > p.len() {
        return None;
    }
    let port_destination = u16::from_be_bytes([p[ihl + 2], p[ihl + 3]]);
    let port_source = u16::from_be_bytes([p[ihl], p[ihl + 1]]);
    if port_destination != 53 {
        return None;
    }
    let udp_long = u16::from_be_bytes([p[ihl + 4], p[ihl + 5]]) as usize;
    if udp_long < 8 || ihl + udp_long > total {
        return None;
    }
    let dns = p[ihl + 8..ihl + udp_long].to_vec();
    if dns.len() < 12 || dns[2] & 0x80 != 0 {
        return None;
    }
    Some(Requete {
        ihl,
        port_source,
        port_destination,
        dns,
    })
}

/// Construit la réponse en échangeant adresses, ports et en recalculant les sommes.
pub fn reponse(p: &[u8], requete: &Requete, dns: &[u8]) -> Vec<u8> {
    let ihl = requete.ihl;
    let taille = ihl + 8 + dns.len();
    let mut r = vec![0u8; taille];
    r[..ihl].copy_from_slice(&p[..ihl]);
    r[2..4].copy_from_slice(&(taille as u16).to_be_bytes());
    r[8] = 64;
    for i in 0..4 {
        r.swap(12 + i, 16 + i);
    }
    r[10] = 0;
    r[11] = 0;
    let somme = !plier(somme16(&r, 0, ihl)) & 0xffff;
    r[10..12].copy_from_slice(&(somme as u16).to_be_bytes());

    r[ihl..ihl + 2].copy_from_slice(&requete.port_destination.to_be_bytes());
    r[ihl + 2..ihl + 4].copy_from_slice(&requete.port_source.to_be_bytes());
    let udp_long = (8 + dns.len()) as u16;
    r[ihl + 4..ihl + 6].copy_from_slice(&udp_long.to_be_bytes());
    r[ihl + 6] = 0;
    r[ihl + 7] = 0;
    r[ihl + 8..].copy_from_slice(dns);

    let mut pseudo = 17u32 + udp_long as u32;
    for i in (12..20).step_by(2) {
        pseudo += u16::from_be_bytes([r[i], r[i + 1]]) as u32;
    }
    let mut somme_udp = !plier((somme16(&r, ihl, udp_long as usize) as u32) + pseudo) & 0xffff;
    if somme_udp == 0 {
        somme_udp = 0xffff;
    }
    r[ihl + 6..ihl + 8].copy_from_slice(&(somme_udp as u16).to_be_bytes());
    r
}

/// Replie une somme en 16 bits (complément à un).
pub fn plier(mut somme: u32) -> u32 {
    while somme >> 16 != 0 {
        somme = (somme & 0xffff) + (somme >> 16);
    }
    somme
}

pub fn somme16(b: &[u8], offset: usize, longueur: usize) -> u32 {
    let mut somme = 0u32;
    let mut i = offset;
    let fin = (offset + longueur).min(b.len());
    while i + 1 < fin {
        somme += u16::from_be_bytes([b[i], b[i + 1]]) as u32;
        i += 2;
    }
    if i < fin {
        somme += (b[i] as u32) << 8;
    }
    plier(somme)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dns() -> Vec<u8> {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for p in ["example", "com"] {
            q.push(p.len() as u8);
            q.extend_from_slice(p.as_bytes());
        }
        q.extend_from_slice(&[0, 0, 1, 0, 1]);
        q
    }

    fn paquet(dns: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; 20 + 8 + dns.len()];
        p[0] = 0x45;
        let taille = p.len() as u16;
        p[2..4].copy_from_slice(&taille.to_be_bytes());
        p[8] = 64;
        p[9] = 17;
        p[12..16].copy_from_slice(&[10, 111, 222, 2]);
        p[16..20].copy_from_slice(&[10, 111, 222, 1]);
        let ip = 0xffff - plier(somme16(&p, 0, 20));
        p[10..12].copy_from_slice(&(ip as u16).to_be_bytes());
        p[20..22].copy_from_slice(&0x3039u16.to_be_bytes());
        p[22..24].copy_from_slice(&53u16.to_be_bytes());
        p[24..26].copy_from_slice(&((8 + dns.len()) as u16).to_be_bytes());
        p[28..].copy_from_slice(dns);
        p
    }

    #[test]
    fn extrait_et_reinjecte() {
        let q = dns();
        let p = paquet(&q);
        let r = extraire(&p).unwrap();
        assert_eq!(r.port_source, 0x3039);
        assert_eq!(r.port_destination, 53);
        assert_eq!(r.dns, q);

        let sortant = reponse(&p, &r, &q);
        assert_eq!(plier(somme16(&sortant, 0, 20)), 0xffff);
        assert_eq!(&sortant[12..16], &[10, 111, 222, 1]);
        assert_eq!(&sortant[16..20], &[10, 111, 222, 2]);
        assert_eq!(u16::from_be_bytes([sortant[20], sortant[21]]), 53);
        assert_eq!(u16::from_be_bytes([sortant[22], sortant[23]]), 0x3039);
        assert_eq!(&sortant[28..], &q);
        assert!(
            extraire(&sortant).is_none(),
            "une réponse n'est pas une requête"
        );
    }

    #[test]
    fn ignore_non_dns() {
        let q = dns();
        let mut p = paquet(&q);
        p[22..24].copy_from_slice(&443u16.to_be_bytes());
        assert!(extraire(&p).is_none());
        let mut tcp = paquet(&q);
        tcp[9] = 6;
        assert!(extraire(&tcp).is_none());
    }

    #[test]
    fn somme_udp_valide() {
        let q = dns();
        let p = paquet(&q);
        let r = extraire(&p).unwrap();
        let s = reponse(&p, &r, &q);
        let udp_long = u16::from_be_bytes([s[24], s[25]]) as usize;
        let mut pseudo = 17u32 + udp_long as u32;
        for i in (12..20).step_by(2) {
            pseudo += u16::from_be_bytes([s[i], s[i + 1]]) as u32;
        }
        assert_eq!(plier(somme16(&s, 20, udp_long) + pseudo), 0xffff);
    }
}
