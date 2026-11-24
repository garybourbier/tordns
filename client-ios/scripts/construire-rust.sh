#!/usr/bin/env bash
# Compile la bibliothèque statique Rust pour la plateforme Apple demandée par
# Xcode (PHASE_SCRIPT) puis la copie dans build/rust/<plateforme>/, d'où
# project.yml la lie. À exécuter sur macOS : la chaîne Apple (SDK iOS, xcrun)
# est indispensable, y compris pour le simulateur.
#
# Hors de Xcode : PLATFORM_NAME=iphoneos ARCHS=arm64 ./construire-rust.sh
set -euo pipefail

ICI=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PLATEFORME="${PLATFORM_NAME:-iphoneos}"
ARCHES="${ARCHS:-arm64}"
SORTIE="$ICI/build/rust/$PLATEFORME"
PROFIL="${CONFIGURATION:-Release}"

case "$PLATEFORME" in
iphoneos) CIBLE_BASE=aarch64-apple-ios ;;
iphonesimulator) CIBLE_BASE=aarch64-apple-ios-sim ;;
*)
	echo "ERREUR : plateforme inconnue : $PLATEFORME" >&2
	exit 1
	;;
esac

if [ "$(uname -s)" != Darwin ]; then
	echo "ERREUR : la compilation iOS exige macOS et Xcode (xcrun absent ici)." >&2
	exit 1
fi
command -v rustup >/dev/null || {
	echo "ERREUR : rustup est requis (cible $CIBLE_BASE)." >&2
	exit 1
}
rustup target add "$CIBLE_BASE" >/dev/null

mkdir -p "$SORTIE"
for arch in $ARCHES; do
	case "$arch/$PLATEFORME" in
	arm64/iphoneos) cible=aarch64-apple-ios ;;
	arm64/iphonesimulator) cible=aarch64-apple-ios-sim ;;
	x86_64/iphonesimulator) cible=x86_64-apple-ios ;;
	*)
		echo "ERREUR : couple architecture/plateforme non pris en charge : $arch/$PLATEFORME" >&2
		exit 1
		;;
	esac
	rustup target add "$cible" >/dev/null
	(cd "$ICI/rust" && cargo build --locked --release --target "$cible")
	computer+=("$ICI/rust/target/$cible/release/libtordns_ios.a")
done

# Plusieurs architectures (Intel + Apple Silicon sur simulateur) : une seule
# bibliothèque universelle, comme le fait Xcode pour ses propres cibles.
(cd "$ICI/rust" && xcrun lipo -create "${computer[@]}" -output "$SORTIE/libtordns_ios.a")
echo "Bibliothèque Tor liée : $SORTIE/libtordns_ios.a ($PROFIL)"
