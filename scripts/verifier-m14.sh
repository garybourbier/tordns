#!/usr/bin/env bash
# TorDNS — preuve de la mission 14 : CI de toutes les plateformes.
#
# Exécute localement ce que la CI exécute : lint, binaires Linux amd64/arm64/
# armv7, paquet .deb installé dans un Debian propre, exe et installateur
# Windows x86_64, APK des trois ABI, images Docker amd64/arm64.
set -euo pipefail

RACINE=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
TMP=$(mktemp -d "${TMPDIR:-/tmp}/tordns-m14.XXXXXX")
trap 'rm -rf "$TMP"' EXIT
VERSION=$(tr -d '[:space:]' <"$RACINE/noeud/VERSION")
export MAKENSIS=${MAKENSIS:-makensis}

section() { printf '\n== %s ==\n' "$*"; }
ok() { printf 'OK : %s\n' "$*"; }
echec() { printf 'ÉCHEC : %s\n' "$*" >&2; exit 1; }

section "1. Lint commun"
"$RACINE/scripts/ci/lint.sh" || echec "lint"
ok "actionlint, shellcheck, gofmt/go vet et cargo fmt verts"

section "2. Client Linux amd64, arm64 et armv7"
for arch in amd64 arm64 armv7; do
	"$RACINE/scripts/ci/client-linux.sh" "$arch" >/dev/null || echec "build Linux $arch"
	ARCHIVE="$RACINE/dist/client-linux/tordns-client_${VERSION}_linux_${arch}.tar.gz"
	[ -s "$ARCHIVE" ] || echec "archive Linux $arch absente"
	tar -tzf "$ARCHIVE" >"$TMP/liste-$arch"
	grep -q 'tordns-client-linux-'"$arch"'/usr/local/bin/tordns-client$' "$TMP/liste-$arch" ||
		echec "archive $arch sans binaire"
	grep -q 'lib/systemd/system/tordns-client.service$' "$TMP/liste-$arch" ||
		echec "archive $arch sans unité systemd"
	tar -xOzf "$ARCHIVE" "tordns-client-linux-$arch/usr/local/bin/tordns-client" >"$TMP/client-$arch"
	chmod +x "$TMP/client-$arch"
	case "$arch" in
		amd64) file "$TMP/client-$arch" | grep -q 'x86-64' || echec "architecture amd64" ;;
		arm64) file "$TMP/client-$arch" | grep -q 'ARM aarch64' || echec "architecture arm64" ;;
		armv7) file "$TMP/client-$arch" | grep -q 'ARM, EABI5' || echec "architecture armv7" ;;
	esac
	file "$TMP/client-$arch" | grep -q 'statically linked' || echec "binaire $arch non statique"
	if [ "$arch" != armv7 ]; then
		DEB="$RACINE/dist/client-linux/tordns-client_${VERSION}_${arch}.deb"
		[ -s "$DEB" ] || echec "paquet $arch absent"
	fi
	ok "$arch : binaire statique et archive"
done

section "3. Paquet .deb amd64 dans un Debian propre"
command -v docker >/dev/null 2>&1 || echec "docker requis pour le test .deb"
docker run --rm -v "$RACINE/dist/client-linux:/dist:ro" debian:bookworm-slim sh -c \
	"dpkg -i /dist/tordns-client_${VERSION}_amd64.deb >/dev/null && tordns-client --version" |
	tee "$TMP/version-deb.txt"
grep -q "tordns-client $VERSION" "$TMP/version-deb.txt" || echec "version du paquet .deb"
ok "dpkg -i accepté, tordns-client --version = $VERSION"

section "4. Client Windows x86_64 et installateur"
"$RACINE/scripts/ci/client-windows.sh" x86_64 >/dev/null || echec "build Windows x86_64"
EXE="$RACINE/dist/client-windows/x86_64/tordns-client.exe"
SETUP="$RACINE/dist/client-windows/x86_64/TorDNS-${VERSION}-x86_64-setup.exe"
[ -s "$EXE" ] || echec "exe Windows absent"
[ -s "$SETUP" ] || echec "installateur NSIS absent"
file "$EXE" | grep -q 'PE32+ executable.*x86-64' || echec "exe Windows non x86-64"
file "$SETUP" | grep -q 'PE32 executable.*MS Windows' || echec "installateur NSIS invalide"
sha256sum "$RACINE/dist/client-windows/x86_64/wintun.dll" |
	grep -q '^e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce' ||
	echec "wintun.dll amd64 inattendue"
ok "exe PE32+ x86-64, installateur NSIS, wintun.dll amd64 épinglée"
printf '%s\n' "NON PROUVÉ : l'installateur aarch64 et son refus sur x64 (pas de chaîne ARM64 locale)."

section "5. APK Android des trois ABI"
"$RACINE/scripts/ci/client-android.sh" >/dev/null || echec "build Android"
for abi in arm64-v8a armeabi-v7a x86_64; do
	APK="$RACINE/dist/client-android/tordns-client-$abi-NON-SIGNE-POUR-PUBLICATION.apk"
	[ -s "$APK" ] || echec "APK $abi absent"
	SO=$(unzip -Z1 "$APK" | grep '^lib/.*/libtordns_arti\.so$')
	[ "$(printf '%s\n' "$SO" | grep -c .)" -eq 1 ] || echec "APK $abi sans .so unique"
	unzip -p "$APK" "$SO" >"$TMP/$abi.so"
	readelf -lW "$TMP/$abi.so" | awk '$1=="LOAD" {print $NF}' | grep -qx '0x4000' ||
		echec "$abi non aligné sur 16 Kio"
	ok "$abi : $SO, LOAD 0x4000"
done
UNIVERSEL="$RACINE/dist/client-android/tordns-client-universel-NON-SIGNE-POUR-PUBLICATION.apk"
[ -s "$UNIVERSEL" ] || echec "APK universel absent"
[ "$(unzip -Z1 "$UNIVERSEL" | grep -c '^lib/.*/libtordns_arti\.so$')" -eq 3 ] ||
	echec "APK universel sans les trois bibliothèques"
ok "APK universel : trois ABI"

section "6. Images Docker amd64 et arm64"
for arch in amd64 arm64; do
	"$RACINE/scripts/ci/noeud-images.sh" "$arch" >/dev/null || echec "images $arch"
	for image in $(docker images --format '{{.Repository}}:{{.Tag}}' | grep ":${arch}$" | grep '^tordns/ci-'); do
		architecture=$(docker image inspect "$image" --format '{{.Architecture}}')
		[ "$architecture" = "$arch" ] || echec "$image en $architecture"
	done
	ok "images $arch construites et inspectées"
done

section "7. Bilan"
printf '%s\n' \
	"Toutes les preuves exécutables ici sont passées." \
	"NON PROUVÉ — à vérifier au premier push : les runners GitHub" \
	"ubuntu-24.04-arm et windows-11-arm, l'exécution réelle d'Action" \
	"(workflow, caches, artifacts), l'installateur aarch64 et son refus sur x64." \
	"Le lint et les compilations locales sont reproductibles, mais un runner" \
	"GitHub peut avoir une version de Rust, de JDK ou de SDK différente."
echo "code=0"
