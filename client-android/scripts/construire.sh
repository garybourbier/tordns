#!/usr/bin/env bash
# Construit les APK TorDNS avec uniquement le SDK Android et cargo, sans
# Gradle. ABIS peut contenir plusieurs ABI ; UNIVERSEL=oui ajoute un APK avec
# toutes les bibliothèques natives.
#
# Prérequis : JDK 17, Android SDK (plateforme 34, build-tools 34+), NDK 26,
# cibles Rust android installées.
set -euo pipefail

RACINE=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SDK="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-/opt/android-sdk}}"
PLATEFORME="${PLATEFORME:-android-34}"
OUTILS="${OUTILS:-$SDK/build-tools/36.1.0}"
[ -d "$OUTILS" ] || OUTILS="$SDK/build-tools/34.0.0"
NDK="${NDK:-$SDK/ndk/26.3.11579264}"
ANDROID_JAR="$SDK/platforms/$PLATEFORME/android.jar"
CONSTRUCTION="$RACINE/build"
ABIS="${ABIS:-arm64-v8a}"
UNIVERSEL="${UNIVERSEL:-non}"
KS="${DEBUG_KEYSTORE:-$HOME/.android/debug.keystore}"

for outil in "$OUTILS/aapt2" "$OUTILS/d8" "$OUTILS/zipalign" "$OUTILS/apksigner" \
	"$ANDROID_JAR" "$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ar"; do
	[ -e "$outil" ] || { echo "ERREUR : outil manquant : $outil" >&2; exit 1; }
done

configurer_abi() {
	case "$1" in
		arm64-v8a)
			TARGET_RUST=aarch64-linux-android
			CLANG="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android26-clang"
			;;
		armeabi-v7a)
			TARGET_RUST=armv7-linux-androideabi
			CLANG="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/armv7a-linux-androideabi26-clang"
			;;
		x86_64)
			TARGET_RUST=x86_64-linux-android
			CLANG="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android26-clang"
			;;
		*) echo "ERREUR : ABI inconnue : $1" >&2; exit 1 ;;
	esac
	[ -x "$CLANG" ] || { echo "ERREUR : compilateur absent : $CLANG" >&2; exit 1; }
	TARGET_ENV=${TARGET_RUST//-/_}
	TARGET_MAJ=${TARGET_ENV^^}
	export "CC_${TARGET_ENV}=$CLANG"
	export "AR_${TARGET_ENV}=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ar"
	export "CARGO_TARGET_${TARGET_MAJ}_LINKER=$CLANG"
	# Android 16 exige des segments LOAD alignés sur 16 Kio pour les .so.
	export "CARGO_TARGET_${TARGET_MAJ}_RUSTFLAGS=-C link-arg=-Wl,--build-id=sha1 -C link-arg=-Wl,-z,max-page-size=16384 -C link-arg=-Wl,-z,common-page-size=16384"
}

echo "== 1. Bibliothèques Tor (Arti) : $ABIS =="
for abi in $ABIS; do
	configurer_abi "$abi"
	echo "-- $abi ($TARGET_RUST)"
	(cd "$RACINE/rust" && cargo build --release --target "$TARGET_RUST")
done

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
	--version-code 2 --version-name 0.2 \
	"$CONSTRUCTION/res.zip"

echo "== 3. Java puis DEX =="
find "$RACINE/app/src/main/java" "$CONSTRUCTION/gen" -name '*.java' -print >"$CONSTRUCTION/sources.txt"
javac --release 11 -Xlint:all -Werror \
	-classpath "$ANDROID_JAR:$RACINE/libs/*" \
	-d "$CONSTRUCTION/classes" \
	@"$CONSTRUCTION/sources.txt"
(cd "$CONSTRUCTION/classes" && jar cf "$CONSTRUCTION/classes.jar" .)
"$OUTILS/d8" --release --min-api 26 --lib "$ANDROID_JAR" \
	--output "$CONSTRUCTION/dex" "$CONSTRUCTION/classes.jar" "$RACINE"/libs/*.jar

echo "== 4. Clé de débogage jetable =="
mkdir -p "$(dirname "$KS")"
if [ ! -f "$KS" ]; then
	keytool -genkeypair -noprompt -keystore "$KS" -storepass android \
		-alias androiddebugkey -keypass android -keyalg RSA -keysize 2048 \
		-validity 10000 -dname "CN=Android Debug,O=Android,C=US" >/dev/null
fi

monter_apk() {
	nom=$1
	shift
	rm -rf "$CONSTRUCTION/apk" "$CONSTRUCTION/unsigned.apk" "$CONSTRUCTION/aligned.apk"
	mkdir -p "$CONSTRUCTION/apk"
	for abi in "$@"; do
		mkdir -p "$CONSTRUCTION/apk/lib/$abi"
		configurer_abi "$abi"
		cp "$RACINE/rust/target/$TARGET_RUST/release/libtordns_arti.so" \
			"$CONSTRUCTION/apk/lib/$abi/"
	done
	cp "$CONSTRUCTION/dex/classes.dex" "$CONSTRUCTION/apk/"
	python3 "$RACINE/scripts/assembler.py" \
		"$CONSTRUCTION/base.apk" "$CONSTRUCTION/apk" "$CONSTRUCTION/unsigned.apk"
	# -P 16 aligne les .so non compressés sur 16 Kio (Android 16).
	"$OUTILS/zipalign" -f -P 16 4 "$CONSTRUCTION/unsigned.apk" "$CONSTRUCTION/aligned.apk"
	"$OUTILS/zipalign" -c -P 16 4 "$CONSTRUCTION/aligned.apk" >/dev/null
	"$OUTILS/apksigner" sign --ks "$KS" --ks-pass pass:android --key-pass pass:android \
		--min-sdk-version 26 --out "$nom" "$CONSTRUCTION/aligned.apk"
	"$OUTILS/apksigner" verify "$nom" >/dev/null
}

echo "== 5. APK par ABI =="
for abi in $ABIS; do
	APK="$CONSTRUCTION/tordns-client-$abi-NON-SIGNE-POUR-PUBLICATION.apk"
	monter_apk "$APK" "$abi"
	echo "APK : $APK"
done
# Compatibilité avec les preuves des missions précédentes (arm64 par défaut).
if [ "$ABIS" = "arm64-v8a" ] && [ -f "$CONSTRUCTION/tordns-client-arm64-v8a-NON-SIGNE-POUR-PUBLICATION.apk" ]; then
	cp "$CONSTRUCTION/tordns-client-arm64-v8a-NON-SIGNE-POUR-PUBLICATION.apk" "$CONSTRUCTION/tordns-client.apk"
fi

if [ "$UNIVERSEL" = oui ]; then
	echo "== 6. APK universel =="
	APK="$CONSTRUCTION/tordns-client-universel-NON-SIGNE-POUR-PUBLICATION.apk"
	# shellcheck disable=SC2086
	monter_apk "$APK" $ABIS
	echo "APK : $APK"
fi
