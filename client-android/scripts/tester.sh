#!/usr/bin/env bash
# Tests hôte (JVM) des briques pures : DNS, cache LRU, paquets IPv4/UDP.
# Aucun Android, aucun appareil, aucun réseau.
set -euo pipefail
RACINE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SORTIE="$RACINE/build/tests-classes"
LIBRAIRIES="${LIBRAIRIES:-$RACINE/build/libs}"
mkdir -p "$SORTIE"
LIBRAIRIES="$LIBRAIRIES" "$RACINE/scripts/telecharger-libs.sh"
javac --release 11 -Xlint:all -Werror -d "$SORTIE" \
    "$RACINE/app/src/main/java/org/tordns/client/DnsMessage.java" \
    "$RACINE/app/src/main/java/org/tordns/client/DnsCache.java" \
    "$RACINE/app/src/main/java/org/tordns/client/Paquet.java" \
    "$RACINE/app/src/main/java/org/tordns/client/Diagnostic.java" \
    "$RACINE/tests/TestLocal.java"
# Validateur DNSSEC : dnsjava + slf4j viennent de build/libs/ (Maven Central,
# empreinte épinglée ; le cache rend les tests suivants hors ligne).
javac --release 11 -Xlint:all -Werror -classpath "$LIBRAIRIES/*" -d "$SORTIE" \
    "$RACINE/app/src/main/java/org/tordns/client/Dnssec.java" \
    "$RACINE/app/src/main/java/org/tordns/client/Arti.java" \
    "$RACINE/tests/TestDnssec.java"
java -cp "$SORTIE:$LIBRAIRIES/*" org.tordns.client.TestLocal
java -cp "$SORTIE:$LIBRAIRIES/*" org.tordns.client.TestDnssec
