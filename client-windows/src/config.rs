//! Configuration simple `clé = valeur`, sans dépendance TOML.

use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub onion: String,
    pub socks: String,
    pub tun: String,
    pub cache: usize,
    pub anti_fuite: bool,
    pub ttl_max_s: u64,
    pub delai_s: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            onion: String::new(),
            socks: "127.0.0.1:9050".into(),
            tun: "TorDNS".into(),
            cache: 4096,
            anti_fuite: false,
            ttl_max_s: 3600,
            delai_s: 15,
        }
    }
}

impl Config {
    /// Fichier par défaut : `%ProgramData%\TorDNS\client.conf`.
    pub fn chemin_defaut() -> std::path::PathBuf {
        let base = std::env::var_os("PROGRAMDATA")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from(r"C:\ProgramData"));
        base.join("TorDNS").join("client.conf")
    }

    pub fn charger(chemin: &std::path::Path) -> Result<Self, String> {
        let texte = std::fs::read_to_string(chemin)
            .map_err(|e| format!("lecture de {} : {e}", chemin.display()))?;
        Self::analyser(&texte)
    }

    pub fn analyser(texte: &str) -> Result<Self, String> {
        let mut c = Config::default();
        let mut vues: HashMap<String, usize> = HashMap::new();
        for (numero, brute) in texte.lines().enumerate() {
            let ligne = brute.split(['#', ';']).next().unwrap_or("").trim();
            if ligne.is_empty() {
                continue;
            }
            let (cle, valeur) = ligne
                .split_once('=')
                .ok_or_else(|| format!("ligne {} : « clé = valeur » attendu", numero + 1))?;
            let cle = cle.trim().to_ascii_lowercase();
            let valeur = valeur.trim();
            *vues.entry(cle.clone()).or_insert(0) += 1;
            match cle.as_str() {
                "onion" => c.onion = valeur.to_ascii_lowercase(),
                "socks" => c.socks = valeur.to_string(),
                "tun" => c.tun = valeur.to_string(),
                "cache" => c.cache = valeur.parse().map_err(|_| "cache invalide")?,
                "anti_fuite" => c.anti_fuite = booléen(valeur)?,
                "ttl_max" => c.ttl_max_s = valeur.parse().map_err(|_| "ttl_max invalide")?,
                "delai" => c.delai_s = valeur.parse().map_err(|_| "delai invalide")?,
                autre => return Err(format!("clé inconnue : {autre}")),
            }
        }
        if c.onion.is_empty() {
            return Err("clé onion manquante".into());
        }
        if !c.onion.ends_with(".onion") {
            return Err("onion doit se terminer par .onion".into());
        }
        if c.socks.is_empty() || !c.socks.contains(':') {
            return Err("socks doit être hôte:port".into());
        }
        if c.cache == 0 {
            return Err("cache doit être supérieur à zéro".into());
        }
        if let Some((cle, _)) = vues.iter().find(|(_, n)| **n > 1) {
            return Err(format!("clé dupliquée : {cle}"));
        }
        Ok(c)
    }
}

fn booléen(valeur: &str) -> Result<bool, String> {
    match valeur.to_ascii_lowercase().as_str() {
        "oui" | "true" | "1" => Ok(true),
        "non" | "false" | "0" => Ok(false),
        _ => Err(format!("booléen invalide : {valeur}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_complete() {
        let c = Config::analyser(
            "# commentaire\nonion = AAAA.onion\nsocks=127.0.0.1:9150\ncache = 128\nanti_fuite = oui\n",
        )
        .unwrap();
        assert_eq!(c.onion, "aaaa.onion");
        assert_eq!(c.socks, "127.0.0.1:9150");
        assert_eq!(c.cache, 128);
        assert!(c.anti_fuite);
        assert_eq!(c.tun, "TorDNS");
    }

    #[test]
    fn refuse_erreurs() {
        assert!(Config::analyser("socks=127.0.0.1:9050\n").is_err());
        assert!(Config::analyser("onion=a.onion\ninconnue=1\n").is_err());
        assert!(Config::analyser("onion=a.onion\nonion=b.onion\n").is_err());
        assert!(Config::analyser("onion=a.onion\ncache=0\n").is_err());
        assert!(Config::analyser("onion=a.onion\nanti_fuite=peut-être\n").is_err());
    }

    #[test]
    fn commentaires_et_valeurs() {
        let c = Config::analyser("onion = x.onion ; fin\nanti_fuite = non\n").unwrap();
        assert!(!c.anti_fuite);
    }
}
