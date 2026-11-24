#!/usr/bin/env bash
# Preuve de la mission 23 — paquet OpenWrt pour routeur.
#
# 1. Construit les cinq binaires Go statiques et les paquets des trois cibles
#    avec le SDK OpenWrt stable (téléchargé, SHA-256 épinglé).
# 2. Vérifie l'architecture de chaque binaire, le contenu et les métadonnées
#    du paquet, la syntaxe du service et de la page LuCI.
# 3. Démarre l'image OpenWrt x86_64 officielle dans QEMU, elle-même lancée
#    dans un conteneur Docker NON privilégié (voir scripts/ci/openwrt-qemu.py),
#    installe le paquet et exécute client-openwrt/testdata/qemu-test.sh :
#    transfert dnsmasq → 127.0.0.1#5353 et anti-fuite DNS/DoT du LAN.
#
# Ce qui ne peut pas être prouvé ici est écrit « NON PROUVÉ » plus bas.
set -euo pipefail

RACINE=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$RACINE"
export GOTOOLCHAIN=go1.23.7
VERSION=$("$RACINE/scripts/ci/version.sh")
OPENWRT_VERSION=${OPENWRT_VERSION:-25.12.6}
IMAGE_URL="https://downloads.openwrt.org/releases/${OPENWRT_VERSION}/targets/x86/64"
IMAGE_NOM="openwrt-${OPENWRT_VERSION}-x86-64-generic-ext4-combined.img.gz"
IMAGE_SHA="f8538784d0288b4133a99ac2a68443e4922ffde6343e80df56a5882364b9d499"
CACHE="$RACINE/dist/openwrt/qemu-cache"
RUN="${OPENWRT_QEMU_RUN:-/tmp/tordns-openwrt-qemu}"

section() { printf '\n== %s ==\n' "$*"; }
ok() { printf 'OK : %s\n' "$*"; }
echec() { printf 'ÉCHEC : %s\n' "$*" >&2; exit 1; }

for outil in go docker file sha256sum curl; do
	command -v "$outil" >/dev/null 2>&1 || echec "$outil requis"
done

section "1. Binaires et paquets"
OPENWRT_TARGETS="ramips/mt7621 mediatek/filogic x86/64" \
	"$RACINE/scripts/ci/client-openwrt.sh" >"$RUN.log" 2>&1 ||
	{ tail -40 "$RUN.log" >&2; echec "construction OpenWrt"; }
grep -E '^(OK :|mipsel_24kc|mips_24kc|arm_cortex-a7|aarch64_cortex-a53|x86_64 )' "$RUN.log" | head -30
for arch in mipsel_24kc mips_24kc arm_cortex-a7 aarch64_cortex-a53 x86_64; do
	b="$RACINE/dist/client-openwrt/binaires/tordns-client.$arch"
	[ -s "$b" ] || echec "binaire $arch absent"
	case "$arch" in
	mipsel_24kc | mips_24kc) motif='MIPS' ;;
	arm_cortex-a7) motif='ARM, EABI5' ;;
	aarch64_cortex-a53) motif='ARM aarch64' ;;
	x86_64) motif='x86-64' ;;
	esac
	desc=$(file -b "$b")
	case "$desc" in
	*"$motif"*) ;;
	*) echec "architecture inattendue pour $arch : $desc" ;;
	esac
	case "$desc" in
	*"statically linked"*) ;;
	*) echec "$arch n'est pas lié statiquement : $desc" ;;
	esac
	ok "$arch statique : $(stat -c '%s' "$b") octets"
done
for arch in mipsel_24kc aarch64_cortex-a53; do
	paquet="$RACINE/dist/client-openwrt/tordns-${VERSION}-r1-${arch}.apk"
	[ -s "$paquet" ] || echec "paquet $arch absent"
done
ok "paquets apk construits pour mipsel_24kc et aarch64_cortex-a53"

section "2. Contenu du paquet"
A="$RACINE/dist/openwrt/sdk-x86/extract/staging_dir/host/bin/apk"
if [ ! -x "$A" ]; then
	mkdir -p "$RACINE/dist/openwrt/sdk-x86/extract"
	tar --zstd -xf \
		"$RACINE/dist/openwrt/cache/openwrt-sdk-${OPENWRT_VERSION}-x86-64_gcc-14.3.0_musl.Linux-x86_64.tar.zst" \
		-C "$RACINE/dist/openwrt/sdk-x86/extract" --strip-components=1
fi
verif="$RUN/paquet"
rm -rf "$verif"
mkdir -p "$verif"
(cd "$verif" && "$A" --allow-untrusted extract \
	"$RACINE/dist/client-openwrt/tordns-${VERSION}-r1-x86_64.apk" >/dev/null)
for f in usr/sbin/tordns-client etc/config/tordns etc/init.d/tordns \
	etc/tordns/anti-fuite.nft.template; do
	[ -e "$verif/$f" ] || echec "fichier $f absent du paquet"
done
[ -x "$verif/usr/sbin/tordns-client" ] || echec "binaire non exécutable dans le paquet"
[ -x "$verif/etc/init.d/tordns" ] || echec "service non exécutable dans le paquet"
file -b "$verif/usr/sbin/tordns-client" | grep -q 'statically linked' ||
	echec "le binaire du paquet n'est pas statique"
ok "contenu du paquet x86_64 conforme"

section "3. Syntaxe"
sh -n "$RACINE/client-openwrt/files/etc/init.d/tordns" ||
	echec "syntaxe shell : service procd"
ok "service procd : syntaxe shell valide"
if command -v node >/dev/null 2>&1; then
	node --check "$RACINE/client-openwrt/luci-app-tordns/htdocs/luci-static/resources/view/tordns/status.js"
	ok "page LuCI : syntaxe JavaScript valide"
else
	printf 'NON PROUVÉ : node absent, syntaxe de la page LuCI non vérifiée\n'
fi
python3 - "$RACINE" <<'PY'
import json, sys, pathlib
r = pathlib.Path(sys.argv[1])
for f in ["client-openwrt/luci-app-tordns/root/usr/share/luci/menu.d/luci-app-tordns.json",
          "client-openwrt/luci-app-tordns/root/usr/share/rpcd/acl.d/luci-app-tordns.json"]:
    json.loads((r / f).read_text())
print("OK : descripteurs LuCI JSON valides")
PY

section "4. Test système dans QEMU (conteneur non privilégié)"
mkdir -p "$CACHE" "$RUN/files"
image="$CACHE/$IMAGE_NOM"
if [ ! -s "$image" ]; then
	curl -fL --retry 3 --max-time 300 "$IMAGE_URL/$IMAGE_NOM" -o "$image.part"
	mv "$image.part" "$image"
fi
printf '%s  %s\n' "$IMAGE_SHA" "$image" | sha256sum -c - >/dev/null ||
	echec "SHA-256 de l'image OpenWrt incorrect"
ok "image OpenWrt ${OPENWRT_VERSION} vérifiée"
if [ ! -s "$RUN/openwrt.img" ]; then
	gzip -dc "$image" >"$RUN/openwrt.img"
fi
cp "$RACINE/dist/client-openwrt/tordns-${VERSION}-r1-x86_64.apk" "$RUN/files/"
cp "$RACINE/client-openwrt/testdata/qemu-test.sh" "$RUN/files/"
(cd "$RACINE/client-openwrt/testdata" &&
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -buildvcs=false -trimpath \
		-ldflags '-s -w' -o "$RUN/files/stub-dns" stub-dns.go)
python3 "$RACINE/scripts/ci/openwrt-qemu.py" --run "$RUN" --attente 900
ok "test système OpenWrt dans QEMU : code=0"

section "NON PROUVÉ"
cat <<'EOF'
- Un vrai routeur matériel (flash, RAM réelle, Tor qui tient dans 256 Mo).
- Le fonctionnement de Tor sur le routeur et la résolution via le .onion :
  le test utilise une adresse factice et un stub à la place du relais pour
  prouver le transfert dnsmasq → 127.0.0.1#5353.
- Les paquets mips et arm ne sont pas construits par le SDK (seules les
  cibles du SDK 25.12.6 ramips/mt7621 et mediatek/filogic sont testées) ;
  leurs binaires Go sont vérifiés par `file` seulement.
- La page LuCI n'est ni construite (elle demande le dépôt feeds/luci) ni
  affichée dans un navigateur.
- La règle nftables est vérifiée sur l'image x86_64 de QEMU (fw4 réel) ;
  son rendu sur un routeur mips/arm n'est pas mesuré.
EOF
echo "code=0"
