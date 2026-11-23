#!/usr/bin/env bash
# TorDNS — fabrique une arborescence de release locale pour les tests.
#   scripts/ci/release-locale.sh v0.0.0-test [dossier]
# Ne contacte aucun serveur et ne signe rien : les fichiers sont factices.
set -euo pipefail

TAG=${1:-v0.0.0-test}
VERSION=${TAG#v}
RACINE=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
DEST=${2:-"$RACINE/dist/release/$TAG"}

printf '%s' "$TAG" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$' ||
	{ echo "ERREUR : tag invalide : $TAG" >&2; exit 1; }

rm -rf "$DEST"
mkdir -p "$DEST"

for arch in amd64 arm64 armv7; do
	printf 'client Linux %s %s\n' "$VERSION" "$arch" >"$DEST/tordns-client-$VERSION-linux-$arch.tar.gz"
done
for arch in amd64 arm64; do
	printf 'paquet Debian %s %s\n' "$VERSION" "$arch" >"$DEST/tordns-client-$VERSION-linux-$arch.deb"
done
printf 'installateur Windows x86_64 %s\n' "$VERSION" >"$DEST/tordns-client-$VERSION-windows-x86_64-setup.exe"
printf 'installateur Windows aarch64 %s\n' "$VERSION" >"$DEST/tordns-client-$VERSION-windows-aarch64-setup.exe"
printf 'binaire macOS universel %s\n' "$VERSION" >"$DEST/tordns-client-$VERSION-macos-universel"
printf 'paquet macOS %s\n' "$VERSION" >"$DEST/tordns-client-$VERSION-macos-universel.pkg"
for abi in arm64-v8a armeabi-v7a x86_64 universel; do
	printf 'APK Android %s %s\n' "$VERSION" "$abi" >"$DEST/tordns-client-$VERSION-android-$abi.apk"
done

DIGEST=$(printf 'test-%s' "$VERSION" | sha256sum | awk '{print $1}')
{
	for image in unbound passerelle etat noeud-tor tor-client; do
		printf '%s=ghcr.io/garybourbier/tordns-%s@sha256:%s\n' "$image" "$image" "$DIGEST"
	done
} >"$DEST/images.txt"

(
	cd "$DEST"
	find . -maxdepth 1 -type f ! -name 'SHA256SUMS*' -printf '%f\n' | sort |
		while IFS= read -r f; do sha256sum "$f"; done >SHA256SUMS.tmp
	mv SHA256SUMS.tmp SHA256SUMS
)

echo "OK : release locale $TAG dans $DEST"
ls -l "$DEST"
echo "code=0"
