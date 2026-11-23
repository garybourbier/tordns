#!/usr/bin/env bash
# Désinstalle le client macOS et restaure les DNS d'origine sauvegardés.
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "ERREUR : lancer avec sudo." >&2; exit 1; }
launchctl bootout system/org.tordns.client 2>/dev/null || true
if [ -x /usr/local/bin/tordns-client ]; then
	/usr/local/bin/tordns-client -restaurer-dns || true
fi
rm -f /Library/LaunchDaemons/org.tordns.client.plist
rm -f /usr/local/libexec/tordns-client-darwin
rm -f /usr/local/bin/tordns-client /usr/local/bin/tordns-client-maj
rm -f "/Library/Application Support/TorDNS/dns-original.json"
echo "Client TorDNS retiré. La configuration client.env est conservée."
