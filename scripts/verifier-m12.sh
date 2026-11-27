#!/usr/bin/env bash
# shellcheck disable=SC1112
# Preuve de la mission 12 : mises à jour Windows/Android, liste d'adresses
# signée, validation DNSSEC côté Linux, Windows et Android.
#
# Tout se fait hors ligne : les manifestes sont signés avec une clé jetable
# créée dans $TMP, les réponses DNSSEC sont des fixtures signées en mémoire.
# Aucun échange avec un nœud, un VPS ou un appareil réel.
set -euo pipefail

RACINE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
export CARGO_NET_OFFLINE=true

section() { printf '\n== %s ==\n' "$*"; }
ok() { printf 'OK : %s\n' "$*"; }
echec() { printf 'ÉCHEC : %s\n' "$*" >&2; exit 1; }

section "1. Client Linux : DNSSEC, adresses signées, compilation"
(
    cd "$RACINE/client-linux"
    go test -count=1 ./...
    go vet ./...
    go build -o "$TMP/tordns-client" .
    go build -o "$TMP/tordns-client-maj" ./cmd/maj
)
"$TMP/tordns-client" -h >/dev/null 2>&1 || true
ok "tests Go (chaîne DNSSEC, fausse adresse, liste signée) et binaires compilés"

section "2. Brique Rust partagée et client Windows"
(
    cd "$RACINE/outils/manifeste-rust"
    cargo test --offline
    cargo build --offline --bin verifier
)
(
    cd "$RACINE/client-windows"
    cargo test --offline
    cargo build --offline --release --target x86_64-pc-windows-gnu
)
cp "$RACINE/client-windows/target/x86_64-pc-windows-gnu/release/tordns-client.exe" "$TMP/"
ok "tests du manifeste, de la mise à jour Windows et du validateur hickory ; exe croisé"

if command -v wine >/dev/null 2>&1; then
    version="$(WINEDEBUG=-all wine "$TMP/tordns-client.exe" --version 2>/dev/null | tr -d '\r')"
    [ "$version" = "tordns-client 0.1.0" ] || echec "exécution Wine inattendue : $version"
    ok "binaire Windows exécuté sous Wine : $version"
else
    printf 'NON PROUVÉ : Wine absent, le binaire Windows n’est pas exécuté.\n'
fi

section "3. Android : tests JVM, APK, symboles JNI"
(
    cd "$RACINE/client-android"
    ./scripts/tester.sh
)
SDK="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-/opt/android-sdk}}"
if [ -f "$SDK/platforms/android-34/android.jar" ]; then
    (cd "$RACINE/client-android" && ./scripts/construire.sh)
    APK="$RACINE/client-android/build/tordns-client.apk"
    OUTILS="$SDK/build-tools/36.1.0"
    [ -x "$OUTILS/apksigner" ] || OUTILS="$SDK/build-tools/34.0.0"
    "$OUTILS/apksigner" verify "$APK"
    badging="$("$OUTILS/aapt2" dump badging "$APK")"
    version="$("$RACINE/scripts/ci/version.sh")"
    code=$(printf '%s' "$version" | awk -F. '{printf "%d", $1*10000 + $2*100 + $3}')
    grep -q "versionCode='$code'" <<<"$badging" ||
        echec "l’APK n’est pas en versionCode $code ($version)"
    unzip -p "$APK" lib/arm64-v8a/libtordns_arti.so > "$TMP/libtordns_arti.so"
    symboles="$(nm -D "$TMP/libtordns_arti.so")"
    grep -q Java_org_tordns_client_Arti_verifierManifeste <<<"$symboles" ||
        echec "symbole JNI de vérification du manifeste absent"
    grep -q Java_org_tordns_client_Arti_telecharger <<<"$symboles" ||
        echec "symbole JNI de téléchargement absent"
    dex="$(unzip -p "$APK" classes.dex | strings)"
    grep -q "Lorg/xbill/DNS/dnssec/ValidatingResolver;" <<<"$dex" ||
        echec "dnsjava absent du dex"
    ok "APK v2 signé, symboles JNI et dnsjava présents"
else
    printf 'NON PROUVÉ : SDK Android absent, APK non construit.\n'
fi

section "4. Manifeste signé par l’outil Go, vérifié par Rust et Go"
(
    cd "$RACINE/outils/publier"
    go build -o "$TMP/signer" .
)
printf 'contenu de test Windows' > "$TMP/client-windows.exe"
printf 'contenu de test Android' > "$TMP/client-android.apk"
COEUR="$(printf 'a%.0s' {1..56}).onion"
COMMUNAUTE="$(printf 'b%.0s' {1..56}).onion"
"$TMP/signer" cle --dossier "$TMP/cles" >/dev/null
"$TMP/signer" manifeste --dossier "$TMP/cles" --version 2 --sortie "$TMP/sortie" \
    --cible "client-windows=$TMP/client-windows.exe,http://exemple.onion/maj/client-windows.exe" \
    --cible "client-android=$TMP/client-android.apk,http://exemple.onion/maj/client-android.apk" \
    --adresse "coeur=$COEUR" --adresse "communaute=$COMMUNAUTE" >/dev/null
CLE="$(tr -d '\n' < "$TMP/cles/publication.pub")"
"$TMP/signer" verifier --manifeste "$TMP/sortie/manifeste.json" \
    --signature "$TMP/sortie/manifeste.json.sig" --cle "$CLE" --version-installee 1 >/dev/null
"$RACINE/outils/manifeste-rust/target/debug/verifier" \
    "$TMP/sortie/manifeste.json" "$TMP/sortie/manifeste.json.sig" "$CLE" 1 >/dev/null
ok "le manifeste Go v2 est accepté par les deux vérificateurs"

if "$RACINE/outils/manifeste-rust/target/debug/verifier" \
    "$TMP/sortie/manifeste.json" "$TMP/sortie/manifeste.json.sig" "$CLE" 2 >/dev/null 2>&1; then
    echec "rejeu de la version 2 accepté"
fi
cp "$TMP/sortie/manifeste.json.sig" "$TMP/sig-fausse"
# Le premier octet est REMPLACÉ par son complément : écrire une valeur fixe
# (0x01) ne modifiait rien une fois sur 256, et le test passait alors sur une
# signature intacte (observé le 27/11).
python3 - "$TMP/sig-fausse" <<'PY'
import sys

chemin = sys.argv[1]
with open(chemin, "rb") as f:
    donnees = bytearray(f.read())
assert len(donnees) == 64, "signature de longueur inattendue"
donnees[0] ^= 0xFF
with open(chemin, "wb") as f:
    f.write(donnees)
PY
if "$RACINE/outils/manifeste-rust/target/debug/verifier" \
    "$TMP/sortie/manifeste.json" "$TMP/sig-fausse" "$CLE" 0 >/dev/null 2>&1; then
    echec "signature altérée acceptée"
fi
ok "rejeu et signature altérée refusés"

section "5. DNSSEC : trois validateurs, réponse menteuse refusée"
(
    cd "$RACINE/client-linux"
    go test -count=1 -v -run 'TestDNSSEC' .
)
(
    cd "$RACINE/client-windows"
    cargo test --offline dnssec -- --nocapture
)
sortie_android="$(cd "$RACINE/client-android" && ./scripts/tester.sh)"
grep -q "DNSSEC Android" <<<"$sortie_android" ||
    echec "tests DNSSEC Android absents"
ok "chaînes valides et négations NSEC/NSEC3 acceptées ; réponses altérées, preuves incomplètes et ancre invalide refusées (Go, Rust, Java)"

section "6. Bilan"
cat <<'BILAN'
Toutes les preuves exécutables ici sont passées.
NON PROUVÉ : l’installation réelle d’une mise à jour Windows sous Windows
(l’installateur NSIS, la tâche planifiée et le redémarrage du service ne sont
pas exécutés ; le binaire est seulement lancé sous Wine) ; l’installation
réelle de l’APK et la session PackageInstaller sur un appareil (l’APK est
construit et signé, les classes sont testées sur JVM) ; le téléchargement par
Tor des mises à jour (les tests utilisent des sources locales) ; la validation
DNSSEC contre les serveurs racine et les zones réelles d’Internet (les chaînes
sont des fixtures signées en mémoire, y compris les négations NSEC/NSEC3) ; la
rotation de clé n’est pas exercée sur un parc réel ; la publication d’un dépôt
F-Droid n’est pas testée.
BILAN
printf 'code=0\n'
