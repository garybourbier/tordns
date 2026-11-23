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
    "$RACINE/app/src/main/java/org/tordns/client/Diagnostic.java" \
    "$RACINE/tests/TestLocal.java"
# Validateur DNSSEC : dnsjava + slf4j sont fournis dans libs/ (aucun réseau).
javac --release 11 -Xlint:all -Werror -classpath "$RACINE/libs/*" -d "$SORTIE" \
    "$RACINE/app/src/main/java/org/tordns/client/Dnssec.java" \
    "$RACINE/app/src/main/java/org/tordns/client/Arti.java" \
    "$RACINE/tests/TestDnssec.java"
java -cp "$SORTIE:$RACINE/libs/*" org.tordns.client.TestLocal
java -cp "$SORTIE:$RACINE/libs/*" org.tordns.client.TestDnssec
