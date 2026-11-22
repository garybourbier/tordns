//! Diagnostic des fuites DNS sous Windows.
//!
//! Les fonctions d'analyse sont pures et testables partout ; `executer` lit
//! `netsh` et le registre. Aucun nom de domaine n'est consulté ni journalisé.

use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Constat {
    pub fuite: bool,
    pub texte: String,
}

fn constat(fuite: bool, texte: impl Into<String>) -> Constat {
    Constat {
        fuite,
        texte: texte.into(),
    }
}

/// Extrait les adresses des sorties `netsh interface ipv4/ipv6 show dnsservers`.
pub fn serveurs(texte: &str) -> Vec<IpAddr> {
    let mut vus = Vec::new();
    for mot in texte.split_whitespace() {
        let propre =
            mot.trim_matches(|c: char| !c.is_ascii_hexdigit() && c != '.' && c != ':' && c != '%');
        if let Ok(ip) = propre.parse::<IpAddr>() {
            if !vus.contains(&ip) {
                vus.push(ip);
            }
        }
    }
    vus
}

fn valeur_registre(sortie: &str, nom: &str) -> Option<String> {
    sortie.lines().find_map(|l| {
        let champs: Vec<&str> = l.split_whitespace().collect();
        if champs.len() >= 3 && champs[0].eq_ignore_ascii_case(nom) {
            Some(champs[2].to_string())
        } else {
            None
        }
    })
}

fn actif(valeur: Option<&String>) -> bool {
    matches!(
        valeur.map(|v| v.to_ascii_lowercase()).as_deref(),
        Some("1") | Some("0x1") | Some("2") | Some("0x2") | Some("yes") | Some("oui")
    )
}

/// Analyse les sorties déjà collectées : serveurs IPv4/IPv6, DoH système,
/// politiques navigateur et « Smart Multi-Homed Name Resolution ».
pub fn analyser(
    ipv4: &str,
    ipv6: &str,
    doh_systeme: &str,
    doh_navigateur: Option<&str>,
    smhnr: &str,
) -> Vec<Constat> {
    let mut constats = Vec::new();
    let mut tous = Vec::new();
    for (famille, texte) in [("IPv4", ipv4), ("IPv6", ipv6)] {
        let serveurs = serveurs(texte);
        for ip in &serveurs {
            let loopback = ip.is_loopback();
            if loopback && ip.is_ipv4() {
                constats.push(constat(false, format!("{famille} : {ip} (TorDNS).")));
            } else if loopback {
                constats.push(constat(
                    true,
                    format!(
                        "{famille} : {ip} n'est pas écouté par TorDNS par défaut ; \
                         utiliser 127.0.0.1 ou configurer le tunnel pour IPv6."
                    ),
                ));
            } else {
                constats.push(constat(
                    true,
                    format!(
                        "{famille} : résolveur {ip} hors TorDNS ; le remplacer par 127.0.0.1 \
                         dans les propriétés de la carte."
                    ),
                ));
            }
            tous.push(*ip);
        }
    }
    if tous.is_empty() {
        constats.push(constat(
            false,
            "aucun résolveur statique déclaré ; vérifier que le tunnel annonce bien 10.111.222.1.",
        ));
    }

    let doh = doh_systeme.to_ascii_lowercase();
    let auto_doh = valeur_registre(doh_systeme, "EnableAutoDoh")
        .map(|v| actif(Some(&v)))
        .unwrap_or(false);
    if auto_doh
        || doh.contains("yes")
        || doh.contains("enabled")
        || doh.contains("oui")
        || doh.contains("activ")
    {
        constats.push(constat(
            true,
            "DoH système Windows actif : Paramètres → Réseau → DNS sécurisé → désactivé \
             (ou EnableAutoDoh=0).",
        ));
    } else {
        constats.push(constat(
            false,
            "DoH système Windows non détecté comme actif.",
        ));
    }

    if let Some(mode) = doh_navigateur {
        if !mode.eq_ignore_ascii_case("off") && !mode.is_empty() {
            constats.push(constat(
                true,
                format!(
                    "DoH d'un navigateur activé par politique ({mode}) : le passer à « off » \
                     (Chrome/Edge : DnsOverHttpsMode=off ; Firefox : network.trr.mode=5)."
                ),
            ));
        }
    }

    let desactive = valeur_registre(smhnr, "DisableSmartNameResolution")
        .map(|v| actif(Some(&v)))
        .unwrap_or(false);
    if desactive {
        constats.push(constat(
            false,
            "Smart Multi-Homed Name Resolution désactivé.",
        ));
    } else {
        constats.push(constat(
            true,
            "Smart Multi-Homed Name Resolution actif : Windows peut interroger plusieurs cartes. \
             Le désactiver (DisableSmartNameResolution=1) et ne laisser que le tunnel.",
        ));
    }
    constats
}

fn commande(programme: &str, args: &[&str]) -> String {
    match std::process::Command::new(programme).args(args).output() {
        Ok(s) => String::from_utf8_lossy(&s.stdout).into_owned(),
        Err(_) => String::new(),
    }
}

#[cfg(windows)]
fn registre(cle: &str, valeur: &str) -> String {
    commande("reg", &["query", cle, "/v", valeur])
}

/// Exécute le diagnostic Windows réel. `--diagnostic` l'appelle puis quitte.
pub fn executer() -> Vec<Constat> {
    #[cfg(windows)]
    {
        let ipv4 = commande("netsh", &["interface", "ipv4", "show", "dnsservers"]);
        let ipv6 = commande("netsh", &["interface", "ipv6", "show", "dnsservers"]);
        let doh = commande("netsh", &["dns", "show", "encryption"]);
        let auto = registre(
            r"HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters",
            "EnableAutoDoh",
        );
        let doh_systeme = format!("{doh}\n{auto}");
        let chrome = registre(r"HKLM\SOFTWARE\Policies\Google\Chrome", "DnsOverHttpsMode");
        let edge = registre(r"HKLM\SOFTWARE\Policies\Microsoft\Edge", "DnsOverHttpsMode");
        let mode_chrome = valeur_registre(&chrome, "DnsOverHttpsMode");
        let mode_edge = valeur_registre(&edge, "DnsOverHttpsMode");
        let mode = mode_chrome.or(mode_edge);
        let smhnr = registre(
            r"HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters",
            "DisableSmartNameResolution",
        );
        analyser(&ipv4, &ipv6, &doh_systeme, mode.as_deref(), &smhnr)
    }
    #[cfg(not(windows))]
    {
        let _ = actif;
        let _ = valeur_registre;
        let _ = commande;
        vec![constat(
            false,
            "diagnostic Windows disponible uniquement dans le binaire compilé pour Windows ; \
             les tests d'analyse tournent sur cet hôte.",
        )]
    }
}

pub fn afficher(constats: &[Constat]) -> usize {
    let mut fuites = 0;
    for c in constats {
        if c.fuite {
            fuites += 1;
            println!("[FUITE] {}", c.texte);
        } else {
            println!("[OK] {}", c.texte);
        }
    }
    if fuites == 0 {
        println!("Bilan : aucune fuite détectée.");
    } else {
        println!("Bilan : {fuites} fuite(s) à fermer.");
    }
    fuites
}

#[cfg(test)]
mod tests {
    use super::*;

    const IPV4: &str = "Configuration for interface \"Ethernet\"\n    Statically Configured DNS Servers: 192.0.2.53\n";
    const IPV6: &str = "Configuration for interface \"Ethernet\"\n    Statically Configured DNS Servers: 2001:db8::53\n";

    #[test]
    fn serveurs_parsees() {
        assert_eq!(
            serveurs(IPV4),
            vec!["192.0.2.53".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(
            serveurs("DNS Servers : 127.0.0.1, ::1\n"),
            vec![
                "127.0.0.1".parse::<IpAddr>().unwrap(),
                "::1".parse::<IpAddr>().unwrap()
            ]
        );
        assert!(serveurs("aucune adresse").is_empty());
    }

    #[test]
    fn machine_qui_fuit() {
        let c = analyser(IPV4, IPV6, "Encryption: Yes", Some("secure"), "");
        let fuites: Vec<_> = c.iter().filter(|c| c.fuite).collect();
        assert!(fuites.len() >= 5, "{c:#?}");
        let texte = c
            .iter()
            .map(|c| c.texte.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(texte.contains("192.0.2.53"));
        assert!(texte.contains("2001:db8::53"));
        assert!(texte.contains("DoH système"));
        assert!(texte.contains("navigateur"));
        assert!(texte.contains("Smart Multi-Homed"));
    }

    #[test]
    fn machine_corrigee() {
        let c = analyser(
            "DNS Servers: 127.0.0.1\n",
            "",
            "Encryption: No",
            Some("off"),
            "DisableSmartNameResolution    REG_DWORD    0x1",
        );
        assert!(c.iter().all(|c| !c.fuite), "{c:#?}");
        assert_eq!(afficher(&c), 0);
    }

    #[test]
    fn registre_est_lu() {
        let sortie = "    DisableSmartNameResolution    REG_DWORD    0x1\n";
        assert_eq!(
            valeur_registre(sortie, "DisableSmartNameResolution").as_deref(),
            Some("0x1")
        );
        assert!(actif(Some(&"0x1".to_string())));
    }
}
