# Chantier 3 — TorDNS distribué : CI/CD, toutes les plateformes, site et README

Cadrage du 23/11/2026 (Claude, à la demande de Gary). Les chantiers 1 et 2 ont livré un nœud
Docker, un réseau redondant et des clients Linux, Android et Windows (architecture :
`chantier-2-cadrage.md`). Le dépôt est **public** sur GitHub (`garybourbier/tordns`).
Ce chantier le rend **téléchargeable par n'importe qui** : chaque plateforme compilée par
GitHub Actions, une page de présentation sur GitHub Pages, un README à jour.

Lire ce fichier en entier avant toute mission, puis la mission demandée, et rien d'autre.

## Règles (toutes les missions)

1. **Aucun secret dans le dépôt ni dans un workflow.** Pas de clé de publication, pas de clé
   APK, pas de certificat Apple, pas de jeton. La **clé Ed25519 de publication reste hors
   ligne chez Gary** : la CI ne signe JAMAIS de manifeste. Un secret GitHub n'est utilisé
   que si la mission le dit, et le workflow doit alors marcher (en sautant l'étape) quand il
   est absent.
2. **Pas de push, pas de tag, pas de release publiée** : tu commites sur `master` en local.
   Claude relit, Gary pousse. Publier une version (tag `vX.Y.Z`, release, image GHCR) est
   un acte de Gary.
3. **Tu ne peux pas lancer GitHub Actions** : chaque workflow est vérifié en local par
   `actionlint` (à installer : binaire officiel, version épinglée) et chaque étape de
   compilation passe par **un script du dépôt** (`scripts/ci/…`) que tu lances toi-même
   sur cette machine pour les cibles qu'elle sait produire. Le YAML ne fait qu'appeler ces
   scripts : jamais de logique de build écrite seulement dans le YAML.
4. **Actions tierces épinglées par empreinte de commit** (`uses: owner/action@<sha40> # vX`),
   `permissions:` minimales par job (`contents: read` par défaut), aucun
   `pull_request_target`, aucune entrée non fiable (`github.event.*.title`, `body`, nom de
   branche) interpolée dans un `run:`.
5. **Zéro journal** des requêtes DNS, partout, toujours (inchangé).
6. **Preuve exigée** : chaque mission finit par `scripts/verifier-mNN.sh` (sortie copiée
   dans le dernier commit). Ce qui ne peut être prouvé qu'une fois sur GitHub (runner macOS,
   Windows ARM, Pages en ligne) est écrit « NON PROUVÉ — à vérifier au premier push ».
7. Une mission = un sujet. Bloqué après trois essais : `docs/missions/journal.md`
   (« à confier à Claude ») et continuer le reste.
8. Français pour les commentaires, les commits, la doc et le site.

## Matrice des plateformes visée

| Produit | Cibles | Format livré |
|---|---|---|
| Nœud (images Docker) | linux/amd64, linux/arm64 | images `ghcr.io/garybourbier/tordns-*`, référencées par empreinte |
| Client Linux (Go) | amd64, arm64, armv7 | binaire statique `.tar.gz` + paquet `.deb` (amd64, arm64) |
| Client Windows (Rust) | x86_64, aarch64 | installateur NSIS par architecture (+ wintun.dll de l'arch.) |
| Client macOS (nouveau, M15) | x86_64, arm64 (binaire universel) | `.pkg` non signé ; notarisation optionnelle |
| Client Android | arm64-v8a, armeabi-v7a, x86_64 | APK par ABI + APK universel |

Chaque release porte un `SHA256SUMS` et une **attestation de provenance** GitHub
(`actions/attest-build-provenance`) pour chaque fichier. Les fichiers ne sont jamais signés
par la CI avec une clé de Gary : la signature APK, la notarisation Apple et le manifeste de
mise à jour se font chez Gary (`outils/`), sur les fichiers téléchargés depuis la release
brouillon, puis Gary publie.

## Missions

| N° | Sujet | Dépend de |
|---|---|---|
| 14 | CI : compilation et tests de toutes les plateformes existantes | — |
| 15 | Client macOS (x86_64 + arm64) | 14 |
| 16 | CD : release brouillon sur tag, images GHCR multi-arch, sommes et attestations | 14, 15 |
| 17 | Site de présentation sur GitHub Pages | 16 |
| 18 | README à jour (toutes plateformes, téléchargements, nœud, sécurité) | 16, 17 |
| 19 | Restes de la relecture Claude du 23/11 (sonde du registre, boucle de mise à jour Linux) | — |
| 20 | Fuzzing de l'analyse DNS (passerelle, clients, registre, manifeste) | 14 |
| 21 | Compilations reproductibles | 16 |
| 22 | Page publique de l'état du réseau (agrégats de sondes, rien sur les utilisateurs) | — |
| 23 | Paquet OpenWrt pour routeur (mips, arm, arm64), anti-fuite LAN | 14 |
| 24 | Image Raspberry Pi prête à flasher pour les nœuds bénévoles | 16 |
| 25 | Publication sur F-Droid | 21 |
| 26 | Client iOS (Network Extension + Arti) | 14 |
| 27 | Dossier pour un audit de sécurité externe (modèle de menace, périmètre, brouillon OTF) | toutes |

Ordre : 19 → 14 → 15 → 16 → 17 → 18 → 20 → 21 → 22 → 23 → 24 → 25 → 26 → 27.
