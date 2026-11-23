#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let coupe = data.len() / 2;
    let brut = &data[..coupe];
    let signature = &data[coupe..];
    let _ = tordns_manifeste::verifier(
        brut,
        signature,
        tordns_manifeste::CLE_PUBLIQUE_EPINGLEE,
        1_800_000_000,
    );
    let _ = tordns_manifeste::verifier(brut, &[], "cle-invalide", 0);
});
