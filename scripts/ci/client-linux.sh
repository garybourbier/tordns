#!/usr/bin/env bash
# TorDNS — compilation du client Linux pour une architecture.
# Appelé à l'identique en local et par GitHub Actions :
#   scripts/ci/client-linux.sh amd64|arm64|armv7
# Sorties : dist/client-linux/ (binaire, archive, paquet .deb amd64/arm64).
set -euo pipefail

RACINE=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
ARCH=${1:-}
DIST=${DIST:-"$RACINE/dist/client-linux"}
VERSION=${VERSION:-$("$RACINE/scripts/ci/version.sh")}
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$("$RACINE/scripts/ci/source-date-epoch.sh")}
export SOURCE_DATE_EPOCH
export GOTOOLCHAIN=go1.23.7
TMP=$(mktemp -d "${TMPDIR:-/tmp}/tordns-linux.XXXXXX")
trap 'rm -rf "$TMP"' EXIT

case "$ARCH" in
	amd64) GOARCH=amd64 GOARM= ;;
	arm64) GOARCH=arm64 GOARM= ;;
	armv7) GOARCH=arm GOARM=7 ;;
	*) echo "ERREUR : architecture attendue amd64, arm64 ou armv7 (reçu '${ARCH}')" >&2; exit 1 ;;
esac

verifier_statique() {
	if command -v readelf >/dev/null 2>&1; then
		if readelf -l "$1" | grep -q 'INTERP'; then
			echo "ERREUR : $1 est dynamique (INTERP présent)" >&2
			exit 1
		fi
	elif command -v file >/dev/null 2>&1; then
		file "$1" | grep -q 'statically linked' || {
			echo "ERREUR : $1 n'est pas statique" >&2
			exit 1
		}
	fi
}

section() { printf '\n== %s ==\n' "$*"; }
section "1. Tests Go (hôte)"
(cd "$RACINE/client-linux" && go test ./... && go vet ./...)

section "2. Binaires Linux/$ARCH statiques"
for binaire in tordns-client tordns-client-maj; do
	if [ "$binaire" = tordns-client-maj ]; then
		(cd "$RACINE/client-linux" && \
			CGO_ENABLED=0 GOOS=linux GOARCH="$GOARCH" GOARM="$GOARM" \
			go build -buildvcs=false -trimpath -ldflags "-s -w -buildid= -X main.version=$VERSION" -o "$TMP/$binaire" ./cmd/maj)
	else
		(cd "$RACINE/client-linux" && \
			CGO_ENABLED=0 GOOS=linux GOARCH="$GOARCH" GOARM="$GOARM" \
			go build -buildvcs=false -trimpath -ldflags "-s -w -buildid= -X main.version=$VERSION" -o "$TMP/$binaire" .)
	fi
	verifier_statique "$TMP/$binaire"
done

section "3. Archive et paquet"
STAGE="$TMP/tordns-client-linux-$ARCH"
mkdir -p "$STAGE/usr/local/bin" "$STAGE/lib/systemd/system" "$STAGE/usr/share/doc/tordns"
install -m 0755 "$TMP/tordns-client" "$TMP/tordns-client-maj" "$STAGE/usr/local/bin/"
install -m 0644 "$RACINE/client-linux/tordns-client.service" \
	"$RACINE/client-linux/tordns-maj-client.service" \
	"$RACINE/client-linux/tordns-maj-client.timer" "$STAGE/lib/systemd/system/"
install -m 0644 "$RACINE/client-linux/README.md" "$STAGE/usr/share/doc/tordns/README.md"

mkdir -p "$DIST"
ARCHIVE="$DIST/tordns-client_${VERSION}_linux_${ARCH}.tar.gz"
tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner \
	-C "$TMP" -cf "$TMP/archive.tar" "tordns-client-linux-$ARCH"
gzip -n -9 <"$TMP/archive.tar" >"$ARCHIVE"

if [ "$ARCH" = amd64 ] || [ "$ARCH" = arm64 ]; then
	DEB="$TMP/deb"
	mkdir -p "$DEB/DEBIAN"
	cp -a "$STAGE/usr" "$DEB/"
	cat >"$DEB/DEBIAN/control" <<EOF
Package: tordns-client
Version: $VERSION
Architecture: $ARCH
Maintainer: TorDNS <tordns@example.invalid>
Section: net
Priority: optional
Recommends: tor
Description: relais DNS local vers le service caché Tor
 Relaie les requêtes DNS vers Tor, avec cache borné, validation DNSSEC,
 refus des fuites et mise à jour signée. Aucun journal de requêtes.
EOF
	(cd "$DEB" && find usr -type f -print0 | sort -z | xargs -0 md5sum >DEBIAN/md5sums)
	printf '2.0\n' >"$TMP/debian-binary"
	# Un paquet Debian attend ./control à la racine de control.tar, pas un
	# sous-dossier DEBIAN/.
	tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner \
		-C "$DEB/DEBIAN" -cJf "$TMP/control.tar.xz" .
	tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner \
		-C "$DEB" -cJf "$TMP/data.tar.xz" ./usr
	(cd "$TMP" && ar rcsD "$DIST/tordns-client_${VERSION}_${ARCH}.deb" \
		debian-binary control.tar.xz data.tar.xz)
fi

section "4. Résultat"
ls -l "$DIST"
if command -v file >/dev/null 2>&1; then
	file "$TMP/tordns-client" "$TMP/tordns-client-maj"
fi
echo "code=0"
