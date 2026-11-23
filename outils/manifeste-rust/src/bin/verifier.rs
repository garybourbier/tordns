//! Vérification hors ligne d'un manifeste signé, pour les preuves et le
//! diagnostic. Usage :
//!   verifier <manifeste> <signature> <clé hex> [version installée]

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 3 {
        eprintln!("usage : verifier <manifeste> <signature> <cle-hex> [version-installee]");
        return ExitCode::from(2);
    }
    let version = args.get(3).and_then(|v| v.parse().ok()).unwrap_or(0);
    let brut = match std::fs::read(&args[0]) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("ERREUR : lecture du manifeste : {e}");
            return ExitCode::FAILURE;
        }
    };
    let sig = match std::fs::read(&args[1]) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("ERREUR : lecture de la signature : {e}");
            return ExitCode::FAILURE;
        }
    };
    match tordns_manifeste::accepter(
        &brut,
        &sig,
        &args[2],
        version,
        tordns_manifeste::maintenant(),
    ) {
        Ok(m) => {
            println!(
                "OK : manifeste v{} valide, expire le {}, {} adresse(s)",
                m.version,
                m.expire,
                m.adresses.len()
            );
            for (nom, adresse) in &m.adresses {
                println!("  {nom} = {adresse}");
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("REFUS : {e}");
            ExitCode::FAILURE
        }
    }
}
