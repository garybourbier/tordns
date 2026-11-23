#!/usr/bin/env bash
# TorDNS — copie optionnelle de l'état du réseau pour GitHub Pages (mission 22).
#
# Lit /reseau et /reseau.json sur le service caché du registre, à travers Tor.
# N'est appelé que si la variable de dépôt TORDNS_PUBLIER_ETAT_RESEAU vaut
# « oui ». L'adresse .onion vient de TORDNS_REGISTRE_ONION : elle n'est jamais
# écrite en dur dans le dépôt.
set -euo pipefail

RACINE=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
ONION=${TORDNS_REGISTRE_ONION:-}
[ -n "$ONION" ] || { echo "ERREUR : TORDNS_REGISTRE_ONION absent" >&2; exit 1; }
printf '%s' "$ONION" | grep -Eq '^[a-z2-7]{56}\.onion$' ||
	{ echo "ERREUR : TORDNS_REGISTRE_ONION n'est pas une adresse v3" >&2; exit 1; }
command -v tor >/dev/null 2>&1 || { echo "ERREUR : tor absent" >&2; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "ERREUR : curl absent" >&2; exit 1; }

TMP=$(mktemp -d "${TMPDIR:-/tmp}/tordns-etat.XXXXXX")
PID=
trap '[ -n "$PID" ] && kill "$PID" 2>/dev/null || true; rm -rf "$TMP"' EXIT INT TERM
mkdir -p "$TMP/tor"
cat >"$TMP/torrc" <<EOF
SocksPort 127.0.0.1:9050
DataDirectory $TMP/tor
Log notice file $TMP/tor.log
EOF
tor -f "$TMP/torrc" >"$TMP/tor.out" 2>&1 &
PID=$!

# Tor ouvre le port SOCKS avant d'avoir un consensus. On retente la vraie
# requête : c'est elle qui prouve que le circuit et le service caché répondent.
ok=0
for _ in $(seq 1 20); do
	if curl --fail --silent --show-error --max-time 90 \
		--socks5-hostname 127.0.0.1:9050 "http://$ONION/reseau.json" \
		-o "$TMP/reseau.json"; then
		ok=1
		break
	fi
	sleep 2
done
[ "$ok" -eq 1 ] || {
	echo "ERREUR : /reseau.json inaccessible par Tor" >&2
	cat "$TMP/tor.log" >&2 || true
	exit 1
}
python3 - "$TMP/reseau.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as f:
    data = json.load(f)
assert data.get("version") == 1, data
for adresse in data.get("adresses", []):
    for noeud in adresse.get("noeuds", []):
        assert len(noeud.get("adresse", "")) <= 9, noeud
for interdit in ("contact", "doutes", "defi"):
    assert interdit not in json.dumps(data), interdit
print("OK : /reseau.json agrégé et sans donnée personnelle")
PY

curl --fail --silent --show-error --max-time 90 \
	--socks5-hostname 127.0.0.1:9050 "http://$ONION/reseau" -o "$TMP/reseau.html"
grep -qi '<svg' "$TMP/reseau.html" || { echo "ERREUR : page sans SVG" >&2; exit 1; }
grep -qi '<script' "$TMP/reseau.html" && { echo "ERREUR : page avec JavaScript" >&2; exit 1; }
install -m 0644 "$TMP/reseau.json" "$RACINE/site/reseau.json"
install -m 0644 "$TMP/reseau.html" "$RACINE/site/reseau.html"
echo "OK : copie publique de l'état du réseau écrite dans site/"
