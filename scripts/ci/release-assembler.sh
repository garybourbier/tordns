#!/usr/bin/env bash
# TorDNS — assemble les artefacts d'une release et écrit SHA256SUMS.
#   VERSION=0.8.0 scripts/ci/release-assembler.sh v0.8.0 [dist/release/v0.8.0]
# Les binaires sont produits par les scripts de scripts/ci/ ; ce script ne fait
# que les renommer selon tordns-<produit>-<version>-<os>-<arch>.<ext>.
set -euo pipefail

RACINE=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
TAG=${1:-}
VERSION=${VERSION:-${TAG#v}}
DEST=${2:-"$RACINE/dist/release/$TAG"}
[ -n "$TAG" ] || { echo "ERREUR : tag obligatoire" >&2; exit 1; }
[ -n "$VERSION" ] || { echo "ERREUR : version obligatoire" >&2; exit 1; }

rm -rf "$DEST"
mkdir -p "$DEST"

copier() {
	source=$1
	nom=$2
	if [ ! -f "$source" ]; then
		# GitHub Actions télécharge les artefacts avec une arborescence
		# variable (à plat ou par architecture) : chercher le nom de base.
		alt=$(find "$RACINE/dist" -type f -name "$(basename "$source")" | head -n 1)
		[ -n "$alt" ] && source=$alt
	fi
	if [ -f "$source" ]; then
		install -m 0644 "$source" "$DEST/$nom"
		echo "OK : $nom"
	else
		echo "ERREUR : fichier attendu absent : $source" >&2
		exit 1
	fi
}

for arch in amd64 arm64 armv7; do
	copier "$RACINE/dist/client-linux/tordns-client_${VERSION}_linux_${arch}.tar.gz" \
		"tordns-client-${VERSION}-linux-${arch}.tar.gz"
done
for arch in amd64 arm64; do
	copier "$RACINE/dist/client-linux/tordns-client_${VERSION}_${arch}.deb" \
		"tordns-client-${VERSION}-linux-${arch}.deb"
done
for arch in x86_64 aarch64; do
	copier "$RACINE/dist/client-windows/$arch/TorDNS-${VERSION}-${arch}-setup.exe" \
		"tordns-client-${VERSION}-windows-${arch}-setup.exe"
done
copier "$RACINE/dist/client-macos/tordns-client-darwin-universel" \
	"tordns-client-${VERSION}-macos-universel"
if [ -f "$RACINE/dist/client-macos/TorDNS-${VERSION}-macos-NON-SIGNE.pkg" ]; then
	copier "$RACINE/dist/client-macos/TorDNS-${VERSION}-macos-NON-SIGNE.pkg" \
		"tordns-client-${VERSION}-macos-universel.pkg"
fi
for abi in arm64-v8a armeabi-v7a x86_64 universel; do
	copier "$RACINE/dist/client-android/tordns-client-${abi}-NON-SIGNE-POUR-PUBLICATION.apk" \
		"tordns-client-${VERSION}-android-${abi}.apk"
done
copier "$RACINE/dist/images.txt" "images.txt"

(
	cd "$DEST"
	find . -maxdepth 1 -type f ! -name 'SHA256SUMS*' -printf '%f\n' | sort |
		while IFS= read -r f; do sha256sum "$f"; done >SHA256SUMS.tmp
	mv SHA256SUMS.tmp SHA256SUMS
)
echo "OK : release assemblée dans $DEST"
echo "code=0"
