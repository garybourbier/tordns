#!/usr/bin/env bash
# Installe le client macOS (launchd + binaires). À lancer avec sudo depuis la
# racine du dépôt, après scripts/ci/client-macos.sh ou depuis un .pkg.
set -euo pipefail

RACINE=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
[ "$(id -u)" -eq 0 ] || { echo "ERREUR : lancer avec sudo." >&2; exit 1; }
case "$(uname -m)" in
	arm64) ARCH=arm64 ;;
	x86_64) ARCH=amd64 ;;
	*) echo "ERREUR : architecture macOS inconnue : $(uname -m)" >&2; exit 1 ;;
esac
BIN="$RACINE/dist/client-macos/tordns-client-darwin-$ARCH"
MAJ="$RACINE/dist/client-macos/tordns-client-maj-darwin-$ARCH"
[ -x "$BIN" ] && [ -x "$MAJ" ] || {
	echo "ERREUR : compiler d'abord avec scripts/ci/client-macos.sh sur macOS." >&2
	exit 1
}

install -d -m 0755 -o root -g wheel /usr/local/bin /usr/local/libexec
install -d -m 0700 -o root -g wheel "/Library/Application Support/TorDNS"
install -d -m 0700 -o root -g wheel "/Library/Application Support/TorDNS/maj"
install -m 0755 -o root -g wheel "$BIN" /usr/local/bin/tordns-client
install -m 0755 -o root -g wheel "$MAJ" /usr/local/bin/tordns-client-maj
install -m 0755 -o root -g wheel "$RACINE/client-macos/launchd/tordns-client-wrapper.sh" \
	/usr/local/libexec/tordns-client-darwin
install -m 0644 -o root -g wheel "$RACINE/client-macos/launchd/org.tordns.client.plist" \
	/Library/LaunchDaemons/org.tordns.client.plist
if [ ! -f "/Library/Application Support/TorDNS/client.env" ]; then
	install -m 0600 -o root -g wheel "$RACINE/client-macos/launchd/client.env.example" \
		"/Library/Application Support/TorDNS/client.env"
	echo "Renseigner TORDNS_ONION dans /Library/Application Support/TorDNS/client.env"
fi
chown root:wheel "/Library/Application Support/TorDNS" "/Library/Application Support/TorDNS/maj"
chmod 0700 "/Library/Application Support/TorDNS" "/Library/Application Support/TorDNS/maj"

launchctl bootout system/org.tordns.client 2>/dev/null || true
launchctl bootstrap system /Library/LaunchDaemons/org.tordns.client.plist
launchctl enable system/org.tordns.client
echo "Service org.tordns.client chargé. Diagnostic : tordns-client -diagnostic"
