#!/usr/bin/env bash
# Construit l'APK TorDNS (arm64-v8a) avec uniquement les outils du SDK Android
# et cargo, sans Gradle ni dépendance de build tierce.
#
# Prérequis : JDK 17, Android SDK (plateforme 34, build-tools 34+), NDK 26,
# cible Rust aarch64-linux-android.
set -euo pipefail

RACINE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SDK="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-/opt/android-sdk}}"
PLATEFORME="${PLATEFORME:-android-34}"
OUTILS="${OUTILS:-$SDK/build-tools/34.0.0}"
NDK="${NDK:-$SDK/ndk/26.3.11579264}"
ANDROID_JAR="$SDK/platforms/$PLATEFORME/android.jar"
CONSTRUCTION="$RACINE/build"
APK="$RACINE/build/tordns-client.apk"

for outil in "$OUTILS/aapt2" "$OUTILS/d8" "$OUTILS/zipalign" "$OUTILS/apksigner" \
             "$ANDROID_JAR" "$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android26-clang"; do
    [ -e "$outil" ] || { echo "ERREUR : outil manquant : $outil" >&2; exit 1; }
done

echo "== 1. Bibliothèque Tor (Arti) pour arm64-v8a =="
export CC_aarch64_linux_android="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android26-clang"
export AR_aarch64_linux_android="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ar"
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$CC_aarch64_linux_android"
# Android 16 exige des segments LOAD alignés sur 16 Kio pour les .so.
export CARGO_TARGET_AARCH64_LINUX_ANDROID_RUSTFLAGS="-C link-arg=-Wl,--build-id=sha1 -C link-arg=-Wl,-z,max-page-size=16384 -C link-arg=-Wl,-z,common-page-size=16384"
(cd "$RACINE/rust" && cargo build --release --target aarch64-linux-android)

echo "== 2. Ressources et R.java =="
rm -rf "$CONSTRUCTION"
mkdir -p "$CONSTRUCTION/gen" "$CONSTRUCTION/classes" "$CONSTRUCTION/dex"
"$OUTILS/aapt2" compile --dir "$RACINE/app/src/main/res" -o "$CONSTRUCTION/res.zip"
"$OUTILS/aapt2" link \
    -o "$CONSTRUCTION/base.apk" \
    -I "$ANDROID_JAR" \
    --manifest "$RACINE/app/src/main/AndroidManifest.xml" \
    --java "$CONSTRUCTION/gen" \
    --min-sdk-version 26 --target-sdk-version 34 --debug-mode \
    --version-code 1 --version-name 0.1 \
    "$CONSTRUCTION/res.zip"

echo "== 3. Java puis DEX =="
trouve_java() { find "$RACINE/app/src/main/java" "$CONSTRUCTION/gen" -name '*.java'; }
# shellcheck disable=SC2046
javac --release 11 -Xlint:all -Werror \
    -classpath "$ANDROID_JAR" \
    -d "$CONSTRUCTION/classes" \
    $(trouve_java)
(cd "$CONSTRUCTION/classes" && jar cf "$CONSTRUCTION/classes.jar" .)
"$OUTILS/d8" --release --min-api 26 --lib "$ANDROID_JAR" \
    --output "$CONSTRUCTION/dex" "$CONSTRUCTION/classes.jar"

echo "== 4. Assemblage de l'APK =="
mkdir -p "$CONSTRUCTION/apk/lib/arm64-v8a"
cp "$RACINE/rust/target/aarch64-linux-android/release/libtordns_arti.so" \
   "$CONSTRUCTION/apk/lib/arm64-v8a/"
cp "$CONSTRUCTION/dex/classes.dex" "$CONSTRUCTION/apk/"
python3 "$RACINE/scripts/assembler.py" \
    "$CONSTRUCTION/base.apk" "$CONSTRUCTION/apk" "$CONSTRUCTION/unsigned.apk"
"$OUTILS/zipalign" -f -p 4 "$CONSTRUCTION/unsigned.apk" "$CONSTRUCTION/aligned.apk"

echo "== 5. Signature (clé de débogage locale, jamais versionnée) =="
KS="${DEBUG_KEYSTORE:-$HOME/.android/debug.keystore}"
if [ ! -f "$KS" ]; then
    mkdir -p "$(dirname "$KS")"
    keytool -genkeypair -noprompt -keystore "$KS" -storepass android \
        -alias androiddebugkey -keypass android -keyalg RSA -keysize 2048 \
        -validity 10000 -dname "CN=Android Debug,O=Android,C=US"
fi
"$OUTILS/apksigner" sign --ks "$KS" --ks-pass pass:android --key-pass pass:android \
    --min-sdk-version 26 --out "$APK" "$CONSTRUCTION/aligned.apk"
"$OUTILS/apksigner" verify --print-certs "$APK" | head -3

echo "APK : $APK"
