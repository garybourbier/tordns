#!/usr/bin/env bash
# TorDNS — binaires et paquets OpenWrt (Mission 23).
#
# Compile le client Linux pour cinq architectures de routeurs, puis construit
# le paquet avec le SDK OpenWrt stable 25.12.6 (gestionnaire apk). Les SDK sont
# téléchargés et vérifiés par SHA-256 ; ils restent dans dist/ (ignoré).
set -euo pipefail

RACINE=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
VERSION=${VERSION:-$("$RACINE/scripts/ci/version.sh")}
SDK_VERSION=${OPENWRT_VERSION:-25.12.6}
BASE_URL="https://downloads.openwrt.org/releases/${SDK_VERSION}/targets"
CACHE=${OPENWRT_CACHE:-"$RACINE/dist/openwrt/cache"}
DIST=${DIST:-"$RACINE/dist/client-openwrt"}
TARGETS_CHOISIES=${OPENWRT_TARGETS:-}
TMP=$(mktemp -d "${TMPDIR:-/tmp}/tordns-openwrt.XXXXXX")
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$CACHE" "$DIST"
rm -f "$DIST"/tordns-*.apk "$DIST"/tordns-*.ipk
rm -rf "$DIST/binaires"
export GOTOOLCHAIN=go1.23.7

section() { printf '\n== %s ==\n' "$*"; }
ok() { printf 'OK : %s\n' "$*"; }
echec() { printf 'ÉCHEC : %s\n' "$*" >&2; exit 1; }

# arch SDK | GOARCH | GOARM | GOMIPS
CIBLES=(
	"ramips/mt7621|mipsel_24kc|mipsle||softfloat"
	"mediatek/filogic|aarch64_cortex-a53|arm64||"
	# Cible supplémentaire pour tester le paquet dans le rootfs x86_64 ; elle
	# n'est pas construite par défaut pour ne pas publier un paquet x86 inutile.
	"x86/64|x86_64|amd64||"
)
BINAIRES=$(cat <<'EOF'
mipsel_24kc|mipsle||softfloat
mips_24kc|mips||softfloat
arm_cortex-a7|arm|7|
aarch64_cortex-a53|arm64||
x86_64|amd64||
EOF
)

section "1. Binaires Go statiques"
while IFS='|' read -r nom goarch goarm gomips; do
	[ -n "$nom" ] || continue
	sortie="$TMP/tordns-client.$nom"
	(
		cd "$RACINE/client-linux"
		CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" GOARM="$goarm" GOMIPS="$gomips" \
			go build -buildvcs=false -trimpath \
			-ldflags "-s -w -buildid= -X main.version=$VERSION" -o "$sortie" .
	)
	[ -s "$sortie" ] || echec "binaire vide pour $nom"
	if command -v readelf >/dev/null 2>&1; then
		readelf -l "$sortie" | grep -q INTERP && echec "$nom est dynamique"
	fi
	mkdir -p "$DIST/binaires"
	cp "$sortie" "$DIST/binaires/tordns-client.$nom"
	printf '%-20s %s\n' "$nom" "$(stat -c '%s' "$sortie") octets"
done <<<"$BINAIRES"
ok "cinq binaires statiques compilés (-s -w, sans UPX)"

for cible in "${CIBLES[@]}"; do
	IFS='|' read -r target arch goarch goarm gomips <<<"$cible"
	if [ -n "$TARGETS_CHOISIES" ]; then
		case " $TARGETS_CHOISIES " in
		*" $target "*) ;;
		*) continue ;;
		esac
	elif [ "$target" = "x86/64" ]; then
		continue
	fi
	fichier="openwrt-sdk-${SDK_VERSION}-$(printf '%s' "$target" | tr '/' '-')_gcc-14.3.0_musl.Linux-x86_64.tar.zst"
	case "$target" in
	ramips/mt7621) sha="e4e3f25962ddf3ed55207fed456ecd1d6e55f3482c976b3183a640df6ef0adf0" ;;
	mediatek/filogic) sha="1c04ac47bdfc361d6aab299eb520d570e368013dedcb8d29cf39dc7168ae642e" ;;
	x86/64) sha="1864152619092e781fa36a401960c8e9ae42d6a364c44ee5f0b197ca5f3c0fcc" ;;
	*) echec "cible sans empreinte SDK : $target" ;;
	esac
	archive="$CACHE/$fichier"
	section "2. SDK $target"
	if [ ! -s "$archive" ]; then
		curl -fL --retry 3 --max-time 300 "$BASE_URL/$target/$fichier" -o "$archive.part"
		mv "$archive.part" "$archive"
	fi
	printf '%s  %s\n' "$sha" "$archive" | sha256sum -c - >/dev/null ||
		echec "SHA-256 du SDK $target incorrect"
	ok "SDK vérifié : $fichier"

	sdk="$TMP/sdk-$(printf '%s' "$target" | tr '/' '-')"
	mkdir -p "$sdk"
	tar --zstd -xf "$archive" -C "$sdk" --strip-components=1
	pkg="$sdk/package/tordns"
	mkdir -p "$pkg"
	cp -a "$RACINE/client-openwrt/Makefile" "$RACINE/client-openwrt/files" "$pkg/"
	cp "$TMP/tordns-client.$arch" "$pkg/files/tordns-client.$arch"

	(cd "$sdk" && make defconfig >/dev/null)
	(cd "$sdk" && TORDNS_VERSION="$VERSION" make package/tordns/compile V=s >"$TMP/build-$arch.log" 2>&1) ||
		{ tail -80 "$TMP/build-$arch.log" >&2; echec "construction du paquet $target"; }
	paquet=$(find "$sdk/bin" -type f \( -name 'tordns-*.apk' -o -name 'tordns-*.ipk' \) | head -n 1)
	[ -n "$paquet" ] || { tail -80 "$TMP/build-$arch.log" >&2; echec "paquet $target absent"; }
	base=$(basename "$paquet")
	ext=${base##*.}
	stem=${base%.*}
	destination="$DIST/${stem}-${arch}.${ext}"
	cp "$paquet" "$destination"
	ok "paquet $(basename "$destination") pour $arch"
done

section "3. Résultat"
ls -lh "$DIST"
for f in "$DIST"/tordns-*.apk "$DIST"/tordns-*.ipk; do
	[ -e "$f" ] || continue
	if command -v sha256sum >/dev/null 2>&1; then sha256sum "$f"; fi
done
echo "code=0"
