//! Preuve hôte : bootstrap Arti puis requête DoH vers un .onion local.
//! Usage : cargo run --example doh -- <adresse>.onion [domaine]
//!
//! Depuis `outils/arti-rust`. L'adresse doit être un service caché de test :
//! aucun nom de domaine réel n'est journalisé, aucun fichier n'est gardé.

use std::time::Duration;

fn requete(domaine: &str) -> Vec<u8> {
    let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for partie in domaine.trim_end_matches('.').split('.') {
        q.push(partie.len() as u8);
        q.extend_from_slice(partie.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 1, 0, 1]);
    q
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let onion = args.get(1).expect("adresse .onion attendue").clone();
    let domaine = args.get(2).cloned().unwrap_or_else(|| "example.com".into());
    let base = std::env::temp_dir().join("tordns-arti-hote");
    std::fs::create_dir_all(&base).unwrap();

    eprintln!("bootstrap Arti (peut prendre 30 à 90 s)…");
    tordns_tor::demarrer(
        base.join("etat").to_str().unwrap(),
        base.join("cache").to_str().unwrap(),
    )
    .expect("bootstrap");
    eprintln!("Tor prêt, POST DoH vers {onion}");

    let reponse =
        tordns_tor::doh(&onion, &requete(&domaine), Duration::from_secs(60)).expect("DoH");
    println!(
        "réponse DoH : {} octets, id 0x{:02x}{:02x}, rcode {}, réponses {}",
        reponse.len(),
        reponse[0],
        reponse[1],
        reponse[3] & 0x0f,
        u16::from_be_bytes([reponse[6], reponse[7]])
    );
}
