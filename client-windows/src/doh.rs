//! POST DoH (RFC 8484) vers `<onion>:80` à travers un proxy SOCKS5 local.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct ClientDoh {
    socks: String,
    onion: String,
    delai: Duration,
}

impl ClientDoh {
    pub fn new(socks: &str, onion: &str, delai: Duration) -> Result<Self, String> {
        let onion = onion.trim().to_ascii_lowercase();
        if !onion.ends_with(".onion") || onion.len() < 8 {
            return Err("adresse .onion invalide".into());
        }
        Ok(Self {
            socks: socks.to_string(),
            onion,
            delai,
        })
    }

    /// Bloquant : renvoie le corps DNS de la réponse 200.
    pub fn poster(&self, requete: &[u8]) -> Result<Vec<u8>, String> {
        if requete.is_empty() {
            return Err("requête DNS vide".into());
        }
        let mut flux = self.connecter()?;
        let entete = format!(
            "POST /dns-query HTTP/1.1\r\nHost: {}\r\nContent-Type: application/dns-message\r\n\
             Accept: application/dns-message\r\nContent-Length: {}\r\n\
             User-Agent: TorDNS-Windows/0.1\r\nConnection: close\r\n\r\n",
            self.onion,
            requete.len()
        );
        flux.write_all(entete.as_bytes())
            .and_then(|_| flux.write_all(requete))
            .map_err(|e| format!("écriture DoH : {e}"))?;

        let mut tampon = Vec::with_capacity(4096);
        let mut bloc = [0u8; 4096];
        let fin_entetes = loop {
            let n = flux
                .read(&mut bloc)
                .map_err(|e| format!("lecture DoH : {e}"))?;
            if n == 0 {
                return Err("réponse DoH tronquée (en-têtes)".into());
            }
            tampon.extend_from_slice(&bloc[..n]);
            if let Some(p) = trouver(&tampon, b"\r\n\r\n") {
                break p + 4;
            }
            if tampon.len() > 16 * 1024 {
                return Err("en-têtes DoH trop volumineux".into());
            }
        };
        let entetes = std::str::from_utf8(&tampon[..fin_entetes])
            .map_err(|_| "en-têtes DoH non UTF-8".to_string())?;
        let statut = entetes.lines().next().unwrap_or("");
        if !statut.contains(" 200 ") {
            return Err(format!("DoH a répondu « {} »", statut.trim()));
        }
        let longueur = content_length(entetes)?;
        if longueur > 64 * 1024 {
            return Err("réponse DoH trop volumineuse".into());
        }
        let mut corps = tampon.split_off(fin_entetes);
        while corps.len() < longueur {
            let n = flux
                .read(&mut bloc)
                .map_err(|e| format!("lecture DoH : {e}"))?;
            if n == 0 {
                return Err("réponse DoH tronquée (corps)".into());
            }
            corps.extend_from_slice(&bloc[..n]);
        }
        corps.truncate(longueur);
        Ok(corps)
    }

    fn connecter(&self) -> Result<TcpStream, String> {
        let adresse = self
            .socks
            .to_socket_addrs()
            .map_err(|e| format!("adresse SOCKS invalide : {e}"))?
            .next()
            .ok_or("adresse SOCKS vide")?;
        let mut flux = TcpStream::connect_timeout(&adresse, self.delai)
            .map_err(|e| format!("connexion SOCKS : {e}"))?;
        flux.set_read_timeout(Some(self.delai))
            .and_then(|_| flux.set_write_timeout(Some(self.delai)))
            .map_err(|e| format!("délais SOCKS : {e}"))?;

        // Poignée de main sans authentification.
        flux.write_all(&[5, 1, 0])
            .map_err(|e| format!("SOCKS : {e}"))?;
        let mut reponse = [0u8; 2];
        flux.read_exact(&mut reponse)
            .map_err(|e| format!("SOCKS : {e}"))?;
        if reponse != [5, 0] {
            return Err("le proxy SOCKS refuse l'authentification sans mot de passe".into());
        }

        // CONNECT par nom (ATYP 3) : Tor résout le .onion lui-même.
        let onion = self.onion.as_bytes();
        if onion.len() > 255 {
            return Err("adresse .onion trop longue".into());
        }
        let mut demande = vec![5, 1, 0, 3, onion.len() as u8];
        demande.extend_from_slice(onion);
        demande.extend_from_slice(&80u16.to_be_bytes());
        flux.write_all(&demande)
            .map_err(|e| format!("SOCKS : {e}"))?;

        let mut entete = [0u8; 4];
        flux.read_exact(&mut entete)
            .map_err(|e| format!("SOCKS : {e}"))?;
        if entete[0] != 5 || entete[1] != 0 {
            return Err(format!("SOCKS : connexion refusée (code {})", entete[1]));
        }
        let a_consommer = match entete[3] {
            1 => 4 + 2,
            3 => {
                let mut l = [0u8; 1];
                flux.read_exact(&mut l)
                    .map_err(|e| format!("SOCKS : {e}"))?;
                l[0] as usize + 2
            }
            4 => 16 + 2,
            _ => return Err("SOCKS : type d'adresse inconnu".into()),
        };
        let mut reste = vec![0u8; a_consommer];
        flux.read_exact(&mut reste)
            .map_err(|e| format!("SOCKS : {e}"))?;
        Ok(flux)
    }
}

fn trouver(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn content_length(entetes: &str) -> Result<usize, String> {
    for ligne in entetes.lines().skip(1) {
        if let Some((nom, valeur)) = ligne.split_once(':') {
            if nom.eq_ignore_ascii_case("content-length") {
                return valeur
                    .trim()
                    .parse()
                    .map_err(|_| "Content-Length invalide".to_string());
            }
        }
    }
    Err("réponse DoH sans Content-Length".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    fn lire_entete(flux: &mut TcpStream) -> Vec<u8> {
        let mut v = Vec::new();
        let mut b = [0u8; 1];
        while !v.ends_with(b"\r\n\r\n") {
            flux.read_exact(&mut b).unwrap();
            v.push(b[0]);
        }
        v
    }

    #[test]
    fn echange_complet_via_socks() {
        let ecoute = TcpListener::bind("127.0.0.1:0").unwrap();
        let adresse = ecoute.local_addr().unwrap();
        let dns = b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00".to_vec();
        let corps_attendu = dns.clone();
        let dns_serveur = dns.clone();

        let serveur = thread::spawn(move || {
            let (mut c, _) = ecoute.accept().unwrap();
            let mut salut = [0u8; 3];
            c.read_exact(&mut salut).unwrap();
            assert_eq!(salut, [5, 1, 0]);
            c.write_all(&[5, 0]).unwrap();

            let mut demande = [0u8; 4];
            c.read_exact(&mut demande).unwrap();
            assert_eq!(&demande[..4], &[5, 1, 0, 3]);
            let mut l = [0u8; 1];
            c.read_exact(&mut l).unwrap();
            let mut nom = vec![0u8; l[0] as usize + 2];
            c.read_exact(&mut nom).unwrap();
            assert!(String::from_utf8_lossy(&nom[..l[0] as usize]).ends_with(".onion"));
            c.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).unwrap();

            let entete = lire_entete(&mut c);
            let texte = String::from_utf8_lossy(&entete);
            assert!(texte.starts_with("POST /dns-query HTTP/1.1"));
            let longueur: usize = texte
                .lines()
                .find_map(|l| {
                    let (n, v) = l.split_once(':')?;
                    n.eq_ignore_ascii_case("content-length")
                        .then(|| v.trim().parse().ok())?
                })
                .unwrap();
            let mut recu = vec![0u8; longueur];
            c.read_exact(&mut recu).unwrap();
            assert_eq!(recu, corps_attendu);

            let mut reponse = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n",
                dns_serveur.len()
            )
            .into_bytes();
            reponse.extend_from_slice(&dns_serveur);
            c.write_all(&reponse).unwrap();
        });

        let client = ClientDoh::new(
            &adresse.to_string(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion",
            Duration::from_secs(5),
        )
        .unwrap();
        let reponse = client.poster(&dns).unwrap();
        assert_eq!(reponse, dns);
        serveur.join().unwrap();
    }

    #[test]
    fn onion_invalide() {
        assert!(ClientDoh::new("127.0.0.1:9050", "example.com", Duration::from_secs(1)).is_err());
    }
}
