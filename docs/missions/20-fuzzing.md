# Mission 20 — Fuzzing de l'analyse DNS

But : trouver les plantages et blocages sur paquets hostiles là où TorDNS lit des données
venues du réseau : passerelle DoH, clients, registre.

## À livrer

- Go (fuzzing natif `go test -fuzz`) : cibles `FuzzPasserelleDoH` (corps POST et paramètre
  `dns=` GET de `serveur/passerelle`), `FuzzRelaisClient` (paquet UDP/TCP reçu par le relais
  local de `client-linux`), `FuzzValiderDNSSEC` (réponse passée à `Valider`), `FuzzEnTeteProxy`
  (en-tête PROXY v2 du registre), `FuzzManifeste` (`manifeste.Verifier` avec signature
  quelconque : ne doit jamais paniquer).
- Rust (`cargo-fuzz`, nightly seulement pour le fuzzing) : décodage DNS du client Windows et
  `tordns_manifeste::verifier`.
- Corpus de départ dans `testdata/fuzz/` : vrais paquets (A, AAAA, NXDOMAIN, réponses
  signées des tests), paquets tronqués, pointeurs de compression en boucle, EDNS énorme.
- Chaque plantage trouvé : corrigé + cas ajouté au corpus de régression (rejoué par
  `go test` normal, sans `-fuzz`).
- `scripts/ci/fuzz.sh <durée>` ; job CI hebdomadaire (`schedule`) de 10 min par cible,
  `permissions: contents: read`, le corpus trouvé est envoyé en artifact.

## Preuve (`scripts/verifier-m20.sh`)

Chaque cible tourne 2 minutes en local sans plantage (ou avec le correctif du plantage
trouvé, décrit dans le commit) ; corpus de régression vert sous `go test`/`cargo test`.
