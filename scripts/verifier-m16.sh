#!/usr/bin/env bash
# Preuves exécutables de la mission 16 (CD, release brouillon, manifeste).
set -euo pipefail

RACINE=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$RACINE"
TMP=$(mktemp -d "${TMPDIR:-/tmp}/tordns-m16.XXXXXX")
trap 'rm -rf "$TMP"' EXIT
echec() { echo "ÉCHEC : $*" >&2; exit 1; }
section() { printf '\n== %s ==\n' "$*"; }

section "1. Workflow et scripts"
./scripts/ci/lint.sh >/dev/null || echec "lint (actionlint/shellcheck) rouge"
grep -q 'tags:' .github/workflows/release.yml || echec "release sans filtre de tag"
grep -q 'pull_request' .github/workflows/release.yml && echec "release déclenchée sur PR"
grep -q 'branches:' .github/workflows/release.yml && echec "release déclenchée sur branche"
grep -q -- '--draft' .github/workflows/release.yml || echec "release non brouillon"
grep -q 'attest-build-provenance' .github/workflows/release.yml || echec "attestation absente"
grep -q 'packages: write' .github/workflows/release.yml || echec "permission packages absente"
grep -q 'id-token: write' .github/workflows/release.yml || echec "permission id-token absente"
grep -Eq 'secrets\.|PRIVATE KEY' .github/workflows/release.yml && echec "secret dans le workflow"
echo "OK : release sur tags seulement, brouillon, attestations, permissions ciblées"

./scripts/ci/verifier-version-tag.sh v0.8.0 >/dev/null || echec "tag v0.8.0 refusé"
if ./scripts/ci/verifier-version-tag.sh v9.9.9 >/dev/null 2>&1; then
	echec "tag incohérent avec noeud/VERSION accepté"
fi
echo "OK : tag cohérent accepté, tag incohérent refusé"

sh -n outils/signer-apk.sh || echec "signer-apk.sh invalide"
grep -q 'apksigner verify' outils/signer-apk.sh || echec "vérification apksigner absente"
grep -q 'SHA256SUMS' outils/signer-apk.sh || echec "sommes non recalculées"
echo "OK : signer-apk.sh signe, vérifie et recalcule les sommes"

./scripts/ci/notes-release.sh v0.8.0 >"$TMP/notes.md"
grep -q '0.8.0' CHANGELOG.md || echec "section CHANGELOG absente"
grep -q 'Client Linux' "$TMP/notes.md" || echec "notes de release vides"
echo "OK : notes de release extraites du CHANGELOG"

grep -q 'TORDNS_IMAGE_UNBOUND' noeud/docker-compose.yml || echec "compose sans image GHCR"
grep -q 'TORDNS_IMAGES' noeud/installer.sh || echec "installeur sans TORDNS_IMAGES"
grep -q -- '--images' noeud/installer.sh || echec "installeur sans option --images"
echo "OK : compose et installeur acceptent les images par empreinte"

section "2. Release locale et sommes"
TAG=v0.0.0-test
./scripts/ci/release-locale.sh "$TAG" "$TMP/release" >/dev/null
[ -f "$TMP/release/SHA256SUMS" ] || echec "SHA256SUMS absent"
[ -f "$TMP/release/images.txt" ] || echec "images.txt absent"
(cd "$TMP/release" && sha256sum -c SHA256SUMS >/dev/null) || echec "sommes locales fausses"
for f in linux-amd64.tar.gz windows-x86_64-setup.exe macos-universel android-universel.apk; do
	ls "$TMP/release"/*"$f" >/dev/null 2>&1 || echec "artefact $f absent"
done
echo "OK : arborescence, SHA256SUMS et images.txt de la release locale"

section "3. Manifeste depuis la release et client Linux"
(cd outils/publier && go build -trimpath -o "$TMP/tordns-signer" .)
"$TMP/tordns-signer" cle --dossier "$TMP/cles" >/dev/null
CLE=$(tr -d '[:space:]' <"$TMP/cles/publication.pub")
"$TMP/tordns-signer" manifeste --depuis-release "$TMP/release" \
	--base-url "https://exemple.invalid/releases/$TAG" --dossier "$TMP/cles" \
	--version 1 --expire 2035-01-01T00:00:00Z --sortie "$TMP/manifeste" >/dev/null
[ -f "$TMP/manifeste/manifeste.json.sig" ] || echec "signature absente"
(cd client-linux && TORDNS_VERIF_MANIFESTE_DIR="$TMP/manifeste" TORDNS_VERIF_CLE="$CLE" \
	go test -run TestManifesteDeRelease .) ||
	echec "manifeste refusé par le client Linux"
echo "OK : manifeste accepté par le client Linux de test"

section "4. Fichier altéré refusé"
cp -a "$TMP/release" "$TMP/release-alteree"
printf 'altere\n' >>"$TMP/release-alteree/tordns-client-0.0.0-test-linux-amd64.tar.gz"
if "$TMP/tordns-signer" manifeste --depuis-release "$TMP/release-alteree" \
	--base-url "https://exemple.invalid/releases/$TAG" --dossier "$TMP/cles" \
	--version 2 --expire 2035-01-01T00:00:00Z --sortie "$TMP/manifeste-altere" >/dev/null 2>&1; then
	echec "fichier altéré accepté"
fi
echo "OK : fichier altéré refusé"

section "5. Bilan"
echo "Toutes les preuves locales de la mission 16 sont passées."
echo "NON PROUVÉ — au premier tag poussé par Gary : exécution réelle du"
echo "workflow, attestations GitHub, push GHCR multi-arch, brouillon de release,"
echo "téléchargement par gh et publication finale."
echo "code=0"
