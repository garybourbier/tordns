#!/usr/bin/env bash
# Preuves exécutables de la mission 21 (deux constructions identiques).
set -euo pipefail

RACINE=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$RACINE"
TMP=$(mktemp -d "${TMPDIR:-/tmp}/tordns-m21.XXXXXX")
trap 'rm -rf "$TMP"' EXIT
echec() { echo "ÉCHEC : $*" >&2; exit 1; }
section() { printf '\n== %s ==\n' "$*"; }
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(./scripts/ci/source-date-epoch.sh)}
MAKENSIS=${MAKENSIS:-makensis}

section "1. Chaînes et horodatages épinglés"
./scripts/ci/lint.sh >/dev/null || echec "lint rouge"
grep -q '^toolchain go1.23.7' client-linux/go.mod || echec "toolchain Go Linux absent"
grep -q '^toolchain go1.23.7' client-macos/go.mod || echec "toolchain Go macOS absent"
grep -q 'GOTOOLCHAIN=go1.23.7' scripts/ci/client-linux.sh || echec "GOTOOLCHAIN Linux absent"
grep -q 'GOTOOLCHAIN=go1.23.7' scripts/ci/client-macos.sh || echec "GOTOOLCHAIN macOS absent"
grep -q 'channel = "1.96.1"' client-windows/rust-toolchain.toml || echec "toolchain Rust absent"
grep -q -- '--locked' scripts/ci/client-windows.sh || echec "cargo non verrouillé"
grep -q 'remap-path-prefix' scripts/ci/client-windows.sh || echec "remap Rust absent"
grep -q 'pe-timestamp.py' scripts/ci/client-windows.sh || echec "timestamp PE non fixé"
grep -q 'SOURCE_DATE_EPOCH' client-android/scripts/assembler.py || echec "ZIP sans date fixe"
grep -q 'ar rcsD' scripts/ci/client-linux.sh || echec "ar non déterministe"
grep -q 'gzip -n' scripts/ci/client-linux.sh || echec "gzip non déterministe"
bases=$(grep -Rh '^FROM ' --include=Dockerfile noeud serveur controleur | wc -l)
epinglees=$(grep -Rh '^FROM ' --include=Dockerfile noeud serveur controleur | grep -c '@sha256:')
[ "$bases" -eq "$epinglees" ] || echec "base Docker non épinglée ($epinglees/$bases)"
echo "OK : Go 1.23.7, Rust 1.96.1, PE, ZIP, ar/gzip et bases Docker épinglés"

section "2. Linux amd64, deux dossiers"
DIST="$TMP/linux1" ./scripts/ci/client-linux.sh amd64 >/dev/null
DIST="$TMP/linux2" ./scripts/ci/client-linux.sh amd64 >/dev/null
for f in "$TMP/linux1"/*; do
	nom=$(basename "$f")
	cmp -s "$f" "$TMP/linux2/$nom" || echec "Linux différent : $nom"
	echo "OK : $nom $(sha256sum "$f" | awk '{print $1}')"
done

section "3. Windows x86_64, deux dossiers"
MAKENSIS="$MAKENSIS" DIST="$TMP/win1" ./scripts/ci/client-windows.sh x86_64 >/dev/null
MAKENSIS="$MAKENSIS" DIST="$TMP/win2" ./scripts/ci/client-windows.sh x86_64 >/dev/null
for f in "$TMP/win1"/*; do
	nom=$(basename "$f")
	cmp -s "$f" "$TMP/win2/$nom" || echec "Windows différent : $nom"
	echo "OK : $nom $(sha256sum "$f" | awk '{print $1}')"
done

section "4. APK non signé, deux constructions"
DIST="$TMP/android1" ./scripts/ci/client-android.sh >/dev/null
DIST="$TMP/android2" ./scripts/ci/client-android.sh >/dev/null
for f in "$TMP/android1"/*; do
	nom=$(basename "$f")
	cmp -s "$f" "$TMP/android2/$nom" || echec "APK différent : $nom"
	if unzip -l "$f" | grep -q 'META-INF/.*\.\(RSA\|DSA\|EC\)'; then
		echec "APK publié signé : $nom"
	fi
	echo "OK : $nom $(sha256sum "$f" | awk '{print $1}')"
done

section "5. Documentation et script de reconstruction"
grep -q 'golang:1.23.7-bookworm@sha256:' scripts/ci/reproduire.sh || echec "conteneur non épinglé"
grep -q 'archive --format=tar' scripts/ci/reproduire.sh || echec "pas d'extraction du tag"
grep -q 'SHA256SUMS' docs/reproduire.md || echec "procédure sans sommes"
grep -q 'NON PROUVÉ\|ne sont pas couvertes\|reste non déterministe' docs/reproduire.md ||
	echec "limites non documentées"
echo "OK : reconstruction depuis le tag et limites documentées"

section "6. Bilan"
echo "Deux constructions successives donnent les mêmes octets pour Linux,"
echo "Windows x86_64 et les APK non signés."
echo "NON PROUVÉ — macOS, la signature Developer ID/notarisation et les images"
echo "multi-arch (Buildx local sans --rewrite-timestamp, CI à confirmer)."
echo "code=0"
