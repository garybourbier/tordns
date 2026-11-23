#!/usr/bin/env bash
# TorDNS — client macOS Intel et Apple Silicon.
#   scripts/ci/client-macos.sh
# Produit les binaires amd64/arm64 ; sur macOS, un binaire universel (lipo)
# et un .pkg non signé si pkgbuild est disponible.
set -euo pipefail

RACINE=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
DIST=${DIST:-"$RACINE/dist/client-macos"}
VERSION=$(tr -d '[:space:]' <"$RACINE/noeud/VERSION")
TMP=$(mktemp -d "${TMPDIR:-/tmp}/tordns-macos.XXXXXX")
trap 'rm -rf "$TMP"' EXIT

section() { printf '\n== %s ==\n' "$*"; }
mkdir -p "$DIST"

section "1. Tests du cœur partagé et des analyseurs macOS"
(cd "$RACINE/client-linux" && go test ./...)
(cd "$RACINE/client-macos" && go test ./...)

section "2. Binaires Mach-O amd64 et arm64"
for arch in amd64 arm64; do
	(cd "$RACINE/client-macos" && \
		GOOS=darwin GOARCH="$arch" CGO_ENABLED=0 \
		go build -trimpath -ldflags "-s -w -X main.version=$VERSION" \
		-o "$DIST/tordns-client-darwin-$arch" .)
	(cd "$RACINE/client-macos" && \
		GOOS=darwin GOARCH="$arch" CGO_ENABLED=0 \
		go build -trimpath -ldflags "-s -w" \
		-o "$DIST/tordns-client-maj-darwin-$arch" ./maj)
	file "$DIST/tordns-client-darwin-$arch"
	file "$DIST/tordns-client-maj-darwin-$arch"
done

section "3. Binaire universel (si lipo est disponible)"
if command -v lipo >/dev/null 2>&1; then
	for b in tordns-client tordns-client-maj; do
		lipo -create "$DIST/$b-darwin-amd64" "$DIST/$b-darwin-arm64" \
			-output "$DIST/$b-darwin-universel"
		file "$DIST/$b-darwin-universel"
	done
else
	echo "lipo absent : deux binaires séparés (NON PROUVÉ pour l'universel)."
fi

section "4. Paquet .pkg (macOS seulement)"
if command -v pkgbuild >/dev/null 2>&1 && command -v productbuild >/dev/null 2>&1; then
	STAGE="$TMP/root"
	install -d "$STAGE/usr/local/bin" "$STAGE/usr/local/libexec" \
		"$STAGE/Library/LaunchDaemons" "$STAGE/Library/Application Support/TorDNS"
	BIN="$DIST/tordns-client-darwin-universel"
	MAJ="$DIST/tordns-client-maj-darwin-universel"
	[ -f "$BIN" ] || BIN="$DIST/tordns-client-darwin-$(uname -m | sed 's/x86_64/amd64/; s/arm64/arm64/')"
	[ -f "$MAJ" ] || MAJ="$DIST/tordns-client-maj-darwin-$(uname -m | sed 's/x86_64/amd64/; s/arm64/arm64/')"
	install -m 0755 "$BIN" "$STAGE/usr/local/bin/tordns-client"
	install -m 0755 "$MAJ" "$STAGE/usr/local/bin/tordns-client-maj"
	install -m 0755 "$RACINE/client-macos/launchd/tordns-client-wrapper.sh" \
		"$STAGE/usr/local/libexec/tordns-client-darwin"
	install -m 0644 "$RACINE/client-macos/launchd/org.tordns.client.plist" \
		"$STAGE/Library/LaunchDaemons/org.tordns.client.plist"
	PKG="$DIST/TorDNS-${VERSION}-macos-NON-SIGNE.pkg"
	pkgbuild --root "$STAGE" --identifier org.tordns.client --version "$VERSION" \
		--scripts "$RACINE/client-macos/installer-pkg" \
		--install-location / "$PKG"
	ls -l "$PKG"
	echo "NON PROUVÉ : signature Developer ID et notarisation Apple (secrets absents)."
else
	echo "pkgbuild/productbuild absents : .pkg non produit ici (NON PROUVÉ sur Linux)."
fi

section "5. Résultat"
ls -l "$DIST"
echo "code=0"
