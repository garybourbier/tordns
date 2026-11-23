#!/usr/bin/env bash
# Preuves de la mission 13 : caches (TTL positif et négatif), diagnostics de
# fuites, et résistance à 10 000 paquets DNS hostiles par client.
# Aucun réseau, aucun nom de domaine, aucune adresse .onion.
set -euo pipefail
RACINE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "== 1. Client Linux : tests unitaires et compilation =="
(cd "$RACINE/client-linux" && go test -count=1 ./...)
(cd "$RACINE/client-linux" && go build -o "$TMP/tordns-client" .)

echo
echo "== 2. Client Windows : tests unitaires et compilation croisée =="
(cd "$RACINE/client-windows" && cargo test --quiet)
(cd "$RACINE/client-windows" && cargo check --quiet --target x86_64-pc-windows-gnu)

echo
echo "== 3. Client Android : tests hôte et compilation de l'interface =="
(cd "$RACINE/client-android" && ./scripts/tester.sh)
SDK="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-/opt/android-sdk}}"
if [ -f "$SDK/platforms/android-34/android.jar" ] && [ -f "$RACINE/client-android/build/gen/org/tordns/client/R.java" ]; then
    mkdir -p "$TMP/android"
    # shellcheck disable=SC2046
    javac --release 11 -Xlint:all -Werror \
        -classpath "$SDK/platforms/android-34/android.jar:$RACINE/client-android/libs/*" \
        -d "$TMP/android" \
        $(find "$RACINE/client-android/app/src/main/java" "$RACINE/client-android/build/gen" -name '*.java')
    echo "Interface Android compilée (javac + android.jar)."
else
    echo "NON PROUVÉ : android.jar ou R.java absent, interface Android non compilée."
fi

echo
echo "== 4. Cache : TTL positif, NXDOMAIN/NODATA et plafond =="
(cd "$RACINE/client-linux" && go test -count=1 -run 'TestCacheable|TestCache' -v ./... | grep -E '^(=== RUN|--- PASS|--- FAIL|ok)')
echo "Tests Windows/Android détaillés : sections 2 et 3."

echo
echo "== 5. Diagnostic Linux sur une machine qui fuit =="
mkdir -p "$TMP/fuite/etc" "$TMP/fuite/run/systemd/resolve"
printf 'nameserver 192.0.2.53\nnameserver ::1\n' > "$TMP/fuite/etc/resolv.conf"
printf 'nameserver 127.0.0.53\n' > "$TMP/fuite/run/systemd/resolve/stub-resolv.conf"
set +e
"$TMP/tordns-client" --diagnostic --racine "$TMP/fuite"
fuite_code=$?
set -e
echo "Code de sortie : $fuite_code (1 attendu : fuites présentes)"
[ "$fuite_code" -eq 1 ]

echo
echo "== 6. Diagnostic Linux sur la même machine corrigée =="
mkdir -p "$TMP/corrige/etc"
printf 'nameserver 127.0.0.1\n' > "$TMP/corrige/etc/resolv.conf"
"$TMP/tordns-client" --diagnostic --racine "$TMP/corrige"
echo "Code de sortie : 0 (attendu)"

echo
echo "== 7. Paquets hostiles : 10 000 entrées aléatoires par client =="
(cd "$RACINE/client-linux" && go test -count=1 -run TestPaquetsDnsHostiles -v ./... | grep -E '^(=== RUN|--- PASS|--- FAIL|ok)')
(cd "$RACINE/client-windows" && cargo test --quiet dix_mille_paquets_dns_hostiles)
(cd "$RACINE/client-android" && ./scripts/tester.sh | grep 'paquets hostiles')

echo
echo "Mission 13 : toutes les preuves sont passées."
echo "NON PROUVÉ : exécution réelle du diagnostic Windows (aucun hôte Windows ici),"
echo "et comportement du DoH/DoT de navigateurs réels (seules les politiques et"
echo "le réglage Android sont inspectés)."
