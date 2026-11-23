# Mission 16 — CD : release brouillon sur tag, images GHCR, sommes et attestations

But : quand Gary pousse un tag `vX.Y.Z`, GitHub construit tout, prépare une **release
brouillon** complète et pousse les images du nœud. Gary signe ce qui doit l'être chez lui,
puis publie la release lui-même.

## À livrer

- `.github/workflows/release.yml`, déclenché **uniquement** par `push` de tags `v*.*.*` :
  - réutilise les scripts de `scripts/ci/` (aucune logique de build propre au workflow) ;
  - nomme les fichiers `tordns-<produit>-<version>-<os>-<arch>.<ext>` ;
  - produit `SHA256SUMS` et une attestation `actions/attest-build-provenance` par fichier
    (`permissions: id-token: write, attestations: write` sur ce job seulement) ;
  - crée la release **en brouillon** (`draft: true`) avec les notes tirées de
    `CHANGELOG.md` (section de la version ; la créer si absente) ; ne la publie jamais ;
  - images : `docker buildx` multi-arch (amd64 + arm64) vers
    `ghcr.io/garybourbier/tordns-<image>:<version>` (+ `latest`), `packages: write` sur ce
    job seulement ; écrit les **empreintes** (`@sha256:…`) obtenues dans
    `dist/images.txt`, joint à la release.
- `outils/publier/` étendu : `tordns-signer manifeste --depuis-release vX.Y.Z` télécharge la
  release brouillon (par `gh` ou HTTPS), vérifie `SHA256SUMS` et les attestations
  (`gh attestation verify`), puis construit le manifeste avec les URL de la release, les
  tailles, les SHA-256 et les empreintes d'images de `images.txt`. Gary le signe hors ligne
  comme aujourd'hui et ajoute `manifeste.json` + `.sig` à la release.
- `outils/signer-apk.sh` : signe les APK téléchargés avec la clé de Gary (chemin en
  argument, jamais dans le dépôt), vérifie avec `apksigner verify`, recalcule les sommes.
- `docs/publier-une-version.md` : la procédure complète de Gary, pas à pas (tag → attendre
  la CI → télécharger → signer APK → manifeste → signer → téléverser → publier la release).
- `noeud/installer.sh` et le `docker-compose.yml` du nœud acceptent les images GHCR
  **par empreinte** (variable `TORDNS_IMAGES=ghcr`), la construction locale restant le
  défaut tant qu'aucune version n'est publiée.

## Refus et pièges à couvrir

Le workflow ne s'exécute pas sur une branche ni une PR ; un tag qui ne correspond pas à
`noeud/VERSION` échoue ; `tordns-signer --depuis-release` refuse une somme ou une attestation
fausse ; aucune clé de signature n'apparaît dans le workflow.

## Preuve (`scripts/verifier-m16.sh`)

`actionlint` vert ; simulation locale d'une release (`scripts/ci/release-locale.sh v0.0.0-test`)
qui produit l'arborescence et `SHA256SUMS` attendus ; `tordns-signer --depuis-release` sur
cette arborescence locale avec une clé jetable → manifeste accepté par le client Linux de
test ; fichier altéré → refus. NON PROUVÉ attendu : attestations réelles, GHCR, brouillon
de release (premier tag poussé par Gary).
