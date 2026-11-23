#!/usr/bin/env bash
# Preuves exécutables de la mission 20 (fuzzing Go et Rust).
set -euo pipefail

RACINE=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$RACINE"
DUREE=${FUZZ_DUREE:-2m}
TMP=$(mktemp -d "${TMPDIR:-/tmp}/tordns-m20.XXXXXX")
trap 'rm -rf "$TMP"' EXIT
echec() { echo "ÉCHEC : $*" >&2; exit 1; }
section() { printf '\n== %s ==\n' "$*"; }

section "1. Corpus de régression et compilation"
./scripts/ci/lint.sh >/dev/null || echec "lint rouge"
for paquet in serveur/passerelle client-linux/relais controleur/registre outils/manifeste; do
	(cd "$paquet" && go test ./...) || echec "tests Go rouges : $paquet"
done
(cd client-windows && cargo test --quiet) || echec "tests Rust Windows rouges"
(cd outils/manifeste-rust && cargo test --quiet) || echec "tests Rust manifeste rouges"
corpus=$(find . -path '*/testdata/fuzz/Fuzz*/*' -type f | wc -l)
[ "$corpus" -ge 10 ] || echec "corpus de départ trop petit ($corpus)"
echo "OK : tests de régression verts, $corpus fichiers de corpus"

section "2. Fuzzing Go (${DUREE} par cible, en parallèle)"
mkdir -p dist/preuves
cibles="FuzzPasserelleDoH FuzzRelaisClient FuzzValiderDNSSEC FuzzEnTeteProxy FuzzManifeste"
for cible in $cibles; do
	(./scripts/ci/fuzz.sh "$DUREE" "$cible" >"dist/preuves/m20-$cible.log" 2>&1;
		echo $? >"$TMP/$cible.status") &
done
wait
for cible in $cibles; do
	statut=$(cat "$TMP/$cible.status" 2>/dev/null || echo 1)
	[ "$statut" -eq 0 ] || { tail -40 "dist/preuves/m20-$cible.log"; echec "$cible a échoué"; }
	tail -2 "dist/preuves/m20-$cible.log"
done
echo "OK : les cinq cibles Go ont tourné sans plantage"

section "3. Fuzzing Rust"
for cible in rust-dns rust-manifeste; do
	./scripts/ci/fuzz.sh "$DUREE" "$cible" >"dist/preuves/m20-$cible.log" 2>&1 ||
		{ tail -40 "dist/preuves/m20-$cible.log"; echec "$cible a échoué"; }
	tail -3 "dist/preuves/m20-$cible.log"
done
if grep -q 'NON PROUVÉ' dist/preuves/m20-rust-*.log; then
	echo "NON PROUVÉ : cargo-fuzz/nightly absent, les cibles Rust n'ont pas tourné ici."
else
	echo "OK : les deux cibles Rust ont tourné sans plantage"
fi

section "4. Workflow hebdomadaire"
grep -q 'schedule:' .github/workflows/fuzz.yml || echec "pas de schedule"
grep -q '10m' .github/workflows/fuzz.yml || echec "durée CI différente de 10 min"
grep -q 'permissions:' .github/workflows/fuzz.yml || echec "permissions absentes"
grep -q 'contents: read' .github/workflows/fuzz.yml || echec "permissions non minimales"
grep -q 'upload-artifact' .github/workflows/fuzz.yml || echec "corpus non archivé"
echo "OK : workflow hebdomadaire, 10 min par cible, corpus en artifact"

section "5. Bilan"
echo "Toutes les preuves locales de la mission 20 sont passées."
echo "NON PROUVÉ — le fuzzing prolongé de la CI (10 min par cible) et les"
echo "cibles Rust si cargo-fuzz/nightly ne sont pas installés sur cette machine."
echo "code=0"
