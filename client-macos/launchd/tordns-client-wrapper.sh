#!/bin/sh
# Lance le client macOS avec la configuration root:wheel, sans exposer la
# configuration dans les arguments du processus.
set -eu
if [ -r "/Library/Application Support/TorDNS/client.env" ]; then
    set -a
    # shellcheck disable=SC1091
    . "/Library/Application Support/TorDNS/client.env"
    set +a
fi
exec /usr/local/bin/tordns-client "$@"
