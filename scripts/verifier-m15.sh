#!/usr/bin/env bash
# TorDNS — preuve de la mission 15 : client macOS.
#
# Sur Linux : tests du cœur partagé, tests des analyseurs networksetup/scutil,
# compilation croisée amd64/arm64 et inspection des Mach-O. Le lancement réel,
# launchd, networksetup, le .pkg et la notarisation restent NON PROUVÉS.
set -euo pipefail

RACINE=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
TMP=$(mktemp -d "${TMPDIR:-/tmp}/tordns-m15.XXXXXX")
trap 'rm -rf "$TMP"' EXIT

section() { printf '\n== %s ==\n' "$*"; }
ok() { printf 'OK : %s\n' "$*"; }
echec() { printf 'ÉCHEC : %s\n' "$*" >&2; exit 1; }

section "1. Cœur partagé Linux/macOS"
(cd "$RACINE/client-linux" && go test ./...) || echec "tests du cœur Linux"
ok "relais, cache, DNS, DNSSEC et adresses signées partagés"

section "2. Analyseurs macOS sur fixtures"
(cd "$RACINE/client-macos" && go test -v \
	-run 'TestParserServicesReseau|TestParserDNSServers|TestSauvegardeApplicationRestauration|TestEtatDNSExistantNEstPasEcrase|TestAnalyseScutil' ./...) ||
	echec "tests des analyseurs macOS"
ok "services networksetup, sauvegarde/restauration DNS et scutil --dns testés hors Mac"

section "3. Compilation croisée et binaires"
"$RACINE/scripts/ci/client-macos.sh" >/dev/null || echec "build macOS"
for arch in amd64 arm64; do
	BIN="$RACINE/dist/client-macos/tordns-client-darwin-$arch"
	MAJ="$RACINE/dist/client-macos/tordns-client-maj-darwin-$arch"
	[ -s "$BIN" ] && [ -s "$MAJ" ] || echec "binaires $arch absents"
	file "$BIN" | grep -q 'Mach-O 64-bit' || echec "binaire $arch non Mach-O"
	case "$arch" in
		amd64) file "$BIN" | grep -q 'x86_64' || echec "binaire amd64 incorrect" ;;
		arm64) file "$BIN" | grep -q 'arm64' || echec "binaire arm64 incorrect" ;;
	esac
	ok "$arch : Mach-O et binaire de mise à jour"
done

section "4. launchd et absence de résolution claire"
python3 - "$RACINE/client-macos/launchd/org.tordns.client.plist" <<'PY'
import plistlib, sys
with open(sys.argv[1], "rb") as f:
    p = plistlib.load(f)
assert p["Label"] == "org.tordns.client"
assert p["ProgramArguments"] == ["/usr/local/libexec/tordns-client-darwin"]
assert p["RunAtLoad"] is True and p["KeepAlive"] is True
PY
grep -q 'networksetup' "$RACINE/client-macos/dns_plan.go" || echec "networksetup absent"
grep -q 'scutil' "$RACINE/client-macos/dns_darwin.go" || echec "scutil absent"
grep -q '"kickstart"' "$RACINE/client-macos/maj/main.go" || echec "mise à jour sans launchctl kickstart"
grep -q 'ProxyJoignable' "$RACINE/client-macos/main_darwin.go" || echec "SOCKS non vérifié avant démarrage"
if grep -Rq 'resolv.conf' "$RACINE/client-macos" --include='*.go'; then
	echec "le client macOS lit encore resolv.conf"
fi
ok "launchd, networksetup, scutil, SOCKS obligatoire, pas de repli resolv.conf"

section "5. Bilan"
printf '%s\n' \
	'Toutes les preuves exécutables sur Linux sont passées.' \
	'NON PROUVÉ — à vérifier sur un Mac / au premier push : lancement réel,' \
	'launchd, networksetup/scutil, restauration DNS après arrêt, binaire' \
	'universel (lipo absent ici), .pkg, signature Developer ID et notarisation.'
echo "code=0"
