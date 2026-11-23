#!/usr/bin/env bash
# TorDNS — tests et APK Android pour arm64-v8a, armeabi-v7a et x86_64.
# Un APK par ABI et un APK universel, signés avec une clé de débogage créée
# dans le répertoire temporaire du job (jamais la clé de publication).
set -euo pipefail

RACINE=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
DIST=${DIST:-"$RACINE/dist/client-android"}
TMP=$(mktemp -d "${TMPDIR:-/tmp}/tordns-android.XXXXXX")
trap 'rm -rf "$TMP"' EXIT

section() { printf '\n== %s ==\n' "$*"; }
section "1. Tests JVM"
(cd "$RACINE/client-android" && ./scripts/tester.sh)

section "2. APK des trois ABI et APK universel"
export ABIS="arm64-v8a armeabi-v7a x86_64"
export UNIVERSEL=oui
export DEBUG_KEYSTORE="$TMP/debug.keystore"
(cd "$RACINE/client-android" && ./scripts/construire.sh)

section "3. Contrôles des bibliothèques et de l'alignement"
OUTILS="${OUTILS:-${ANDROID_SDK_ROOT:-${ANDROID_HOME:-/opt/android-sdk}}/build-tools/36.1.0}"
[ -d "$OUTILS" ] || OUTILS="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-/opt/android-sdk}}/build-tools/34.0.0"
for apk in "$RACINE"/client-android/build/tordns-client-*-NON-SIGNE-POUR-PUBLICATION.apk; do
	[ -s "$apk" ] || { echo "ERREUR : APK absent : $apk" >&2; exit 1; }
	"$OUTILS/zipalign" -c -P 16 4 "$apk" >/dev/null
	unzip -l "$apk" | awk '/lib\/.*\/libtordns_arti\.so$/ { print $4 }'
done
for abi in arm64-v8a armeabi-v7a x86_64; do
	APK="$RACINE/client-android/build/tordns-client-$abi-NON-SIGNE-POUR-PUBLICATION.apk"
	n=$(unzip -l "$APK" | awk '/lib\/.*\/libtordns_arti\.so$/ { n++ } END { print n+0 }')
	[ "$n" -eq 1 ] || { echo "ERREUR : $abi contient $n bibliothèques natives" >&2; exit 1; }
done
UNIVERSEL="$RACINE/client-android/build/tordns-client-universel-NON-SIGNE-POUR-PUBLICATION.apk"
n=$(unzip -l "$UNIVERSEL" | awk '/lib\/.*\/libtordns_arti\.so$/ { n++ } END { print n+0 }')
[ "$n" -eq 3 ] || { echo "ERREUR : APK universel contient $n bibliothèques natives" >&2; exit 1; }

mkdir -p "$DIST"
cp "$RACINE"/client-android/build/tordns-client-*-NON-SIGNE-POUR-PUBLICATION.apk "$DIST/"
ls -l "$DIST"
echo "code=0"
