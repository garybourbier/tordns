#!/usr/bin/env bash
# Tests hôte (JVM) des briques pures : DNS, cache LRU, paquets IPv4/UDP.
# Aucun Android, aucun appareil, aucun réseau.
set -euo pipefail
RACINE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SORTIE="$RACINE/build/tests-classes"
mkdir -p "$SORTIE"
javac --release 11 -Xlint:all -Werror -d "$SORTIE" \
    "$RACINE/app/src/main/java/org/tordns/client/DnsMessage.java" \
    "$RACINE/app/src/main/java/org/tordns/client/DnsCache.java" \
    "$RACINE/app/src/main/java/org/tordns/client/Paquet.java" \
    "$RACINE/tests/TestLocal.java"
java -cp "$SORTIE" org.tordns.client.TestLocal
