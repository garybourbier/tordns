#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = tordns_win::dns::analyser(data);
    let _ = tordns_win::dns::cacheable(data);
    let _ = tordns_win::dns::ttl_reponse(data);
    let _ = tordns_win::dns::ttl_negatif(data);
    let _ = tordns_win::dns::duree_cache(data, 3_600_000);
    let _ = tordns_win::dns::avec_id(data, 7);
    let _ = tordns_win::dns::servfail(data);
    let _ = tordns_win::paquet::extraire(data);
});
