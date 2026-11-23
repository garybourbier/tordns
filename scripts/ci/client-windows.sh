#!/usr/bin/env bash
# TorDNS — compilation du client Windows et de son installateur NSIS.
#   scripts/ci/client-windows.sh x86_64|aarch64
# En local Linux, la cible x86_64 est compilée par MinGW ; aarch64 exige un
# hôte Windows ARM64 (ou un compilateur croisé absent de cette machine).
set -euo pipefail

RACINE=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
ARCH=${1:-}
DIST=${DIST:-"$RACINE/dist/client-windows/$ARCH"}
VERSION=${VERSION:-$("$RACINE/scripts/ci/version.sh")}
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$("$RACINE/scripts/ci/source-date-epoch.sh")}
export SOURCE_DATE_EPOCH
if command -v python3 >/dev/null 2>&1; then PYTHON=python3; elif command -v python >/dev/null 2>&1; then PYTHON=python; else
	echo "ERREUR : python3/python requis pour fixer l'horodatage PE" >&2; exit 1
fi
PE_SCRIPT="$RACINE/scripts/ci/pe-timestamp.py"
if command -v cygpath >/dev/null 2>&1; then PE_SCRIPT=$(cygpath -w "$PE_SCRIPT"); fi
WINTUN_URL="https://www.wintun.net/builds/wintun-0.14.1.zip"
WINTUN_ZIP_SHA256="07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"
TMP=$(mktemp -d "${TMPDIR:-/tmp}/tordns-win.XXXXXX")
trap 'rm -rf "$TMP"' EXIT

case "$ARCH" in
	x86_64) WINTUN_DIR=amd64; WINTUN_SHA256="e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce" ;;
	aarch64) WINTUN_DIR=arm64; WINTUN_SHA256="f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80" ;;
	*) echo "ERREUR : architecture attendue x86_64 ou aarch64 (reçu '${ARCH}')" >&2; exit 1 ;;
esac

case "$(uname -s)" in
	MINGW*|MSYS*|CYGWIN*) CIBLE="${ARCH}-pc-windows-msvc" ;;
	*) CIBLE="x86_64-pc-windows-gnu" ;;
esac
if [ "$ARCH" = aarch64 ] && [ "$CIBLE" = x86_64-pc-windows-gnu ]; then
	echo "ERREUR : aarch64 Windows doit être compilé sur Windows ARM64 (NON PROUVÉ en local)." >&2
	exit 1
fi

section() { printf '\n== %s ==\n' "$*"; }

section "1. Tests Rust (hôte)"
(cd "$RACINE/client-windows" && cargo test --locked)

section "2. Binaire Windows $ARCH ($CIBLE)"
rustup target add "$CIBLE" >/dev/null 2>&1 || true
case "$CIBLE" in
	*-gnu) HORODATAGE="-C link-arg=-Wl,--no-insert-timestamp" ;;
	*) HORODATAGE="-C link-arg=/Brepro" ;;
esac
(cd "$RACINE/client-windows" && \
	RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$RACINE=. -C debuginfo=0 $HORODATAGE" \
	cargo build --release --locked --target "$CIBLE")
EXE="$RACINE/client-windows/target/$CIBLE/release/tordns-client.exe"
[ -s "$EXE" ] || { echo "ERREUR : exe absent : $EXE" >&2; exit 1; }
mkdir -p "$DIST"
install -m 0755 "$EXE" "$DIST/tordns-client.exe"
EXE_WIN="$DIST/tordns-client.exe"
if command -v cygpath >/dev/null 2>&1; then EXE_WIN=$(cygpath -w "$EXE_WIN"); fi
"$PYTHON" "$PE_SCRIPT" "$EXE_WIN" "$SOURCE_DATE_EPOCH"

section "3. wintun.dll $WINTUN_DIR (SHA-256 épinglé)"
ZIP="$TMP/wintun.zip"
curl -fsSL --max-time 120 "$WINTUN_URL" -o "$ZIP"
ACTUEL=$(sha256sum "$ZIP" | awk '{print $1}')
[ "$ACTUEL" = "$WINTUN_ZIP_SHA256" ] || {
	echo "ERREUR : SHA-256 de wintun.zip inattendu : $ACTUEL" >&2
	exit 1
}
if command -v unzip >/dev/null 2>&1; then
	unzip -p "$ZIP" "wintun/bin/$WINTUN_DIR/wintun.dll" >"$DIST/wintun.dll"
elif command -v powershell >/dev/null 2>&1; then
	EXTRAIT="$TMP/wintun"
	powershell -NoProfile -NonInteractive -Command \
		"Expand-Archive -LiteralPath '$(cygpath -w "$ZIP" 2>/dev/null || printf '%s' "$ZIP")' -DestinationPath '$(cygpath -w "$EXTRAIT" 2>/dev/null || printf '%s' "$EXTRAIT")' -Force" >/dev/null
	cp "$EXTRAIT/wintun/bin/$WINTUN_DIR/wintun.dll" "$DIST/wintun.dll"
else
	echo "ERREUR : ni unzip ni powershell pour extraire wintun.zip" >&2
	exit 1
fi
ACTUEL=$(sha256sum "$DIST/wintun.dll" | awk '{print $1}')
[ "$ACTUEL" = "$WINTUN_SHA256" ] || {
	echo "ERREUR : SHA-256 de wintun.dll inattendu : $ACTUEL" >&2
	exit 1
}

section "4. Installateur NSIS $ARCH"
MAKENSIS=${MAKENSIS:-makensis}
command -v "$MAKENSIS" >/dev/null 2>&1 || {
	echo "ERREUR : makensis absent (paquet nsis requis)." >&2
	exit 1
}
SORTIE="$DIST/TorDNS-${VERSION}-${ARCH}-setup.exe"
BINAIRE="$DIST/tordns-client.exe"
WINTUN="$DIST/wintun.dll"
if command -v cygpath >/dev/null 2>&1; then
	BINAIRE=$(cygpath -w "$BINAIRE")
	WINTUN=$(cygpath -w "$WINTUN")
	SORTIE=$(cygpath -w "$SORTIE")
fi
touch -d "@$SOURCE_DATE_EPOCH" "$BINAIRE" "$WINTUN"
(cd "$RACINE/client-windows/installateur" && \
	"$MAKENSIS" "-DARCH=$ARCH" "-DVERSION=$VERSION" "-DBINAIRE=$BINAIRE" \
		"-DWINTUN=$WINTUN" "-DSORTIE=$SORTIE" tordns.nsi)
[ -s "$SORTIE" ] || { echo "ERREUR : installateur absent : $SORTIE" >&2; exit 1; }
"$PYTHON" "$PE_SCRIPT" "$SORTIE" "$SOURCE_DATE_EPOCH"

section "5. Résultat"
ls -l "$DIST"
echo "code=0"
