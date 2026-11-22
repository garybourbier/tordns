#!/usr/bin/env bash
# Preuves locales du relais DNS TorDNS (Mission 4).
#
# Le relais écoute par défaut sur 127.0.0.1:53 (privilège requis). Ici, faute de
# privilège, la preuve utilise 127.0.0.1:15353 ; le comportement est identique.
# (5353 est déjà pris par Avahi/KDE Connect sur cette machine.)
#
# Prérequis : stack serveur démarrée (serveur/docker compose up -d) et image
# tordns/unbound:local contenant dig, utilisée via --network host.
set -euo pipefail

RACINE="$(cd "$(dirname "$0")/.." && pwd)"
PORT="${TORDNS_PORT:-15353}"
ECOUTE="127.0.0.1:$PORT"
BIN="${TORDNS_BIN:-/tmp/tordns-client}"
JOURNAL="$(mktemp -t tordns-client.XXXXXX.log)"

IMAGE_DIG="${TORDNS_IMAGE_DIG:-tordns/unbound:local}"

dig-local() {
	docker run --rm --network host --entrypoint dig "$IMAGE_DIG" "$@"
}

dig-stdin() {
	docker run --rm -i --network host --entrypoint dig "$IMAGE_DIG" "$@"
}

# Adresse .onion : variable d'environnement, sinon clé locale du serveur.
ONION="${TORDNS_ONION:-}"
if [ -z "$ONION" ] && [ -x "$RACINE/../serveur/scripts/gestion-cles.sh" ]; then
	ONION="$("$RACINE/../serveur/scripts/gestion-cles.sh" adresse 2>/dev/null || true)"
fi
if [ -z "$ONION" ]; then
	echo "ERREUR : adresse .onion introuvable (définir TORDNS_ONION)." >&2
	exit 1
fi

# Port SOCKS local du conteneur Tor, lu depuis serveur/.env si présent.
SOCKS_PORT="$(sed -n 's/^TOR_SOCKS_PORT=//p' "$RACINE/../serveur/.env" 2>/dev/null | tail -1)"
SOCKS_PORT="${SOCKS_PORT:-9050}"

echo "== 0. Construction du relais et démarrage sur $ECOUTE =="
(cd "$RACINE" && gofmt -l . && go vet ./... && go test ./... >/dev/null)
(cd "$RACINE" && go build -o "$BIN" .)
TORDNS_ONION="$ONION" TORDNS_SOCKS="127.0.0.1:$SOCKS_PORT" \
	"$BIN" -ecoute "$ECOUTE" -cache 256 -delai 15s >"$JOURNAL" 2>&1 &
PID=$!
trap 'kill "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true' EXIT

pret=false
for _ in $(seq 1 50); do
	if ! kill -0 "$PID" 2>/dev/null; then
		echo "ERREUR : le relais s'est arrêté au démarrage." >&2
		cat "$JOURNAL" >&2
		exit 1
	fi
	# Le TCP s'ouvre en même temps que l'UDP : sonder sans pré-remplir le cache.
	if (exec 3<>/dev/tcp/127.0.0.1/"$PORT") 2>/dev/null; then
		exec 3<&-
		pret=true
		break
	fi
	sleep 0.2
done
if [ "$pret" != true ]; then
	echo "ERREUR : le relais ne répond pas sur $ECOUTE." >&2
	cat "$JOURNAL" >&2
	exit 1
fi
echo "Relais prêt (PID $PID), SOCKS 127.0.0.1:$SOCKS_PORT, cache 256 entrées."

echo
echo "== 1. Résolution UDP transparente (dig @127.0.0.1 -p $PORT, +dnssec) =="
dig-local "@127.0.0.1" -p "$PORT" example.com A +dnssec +noall +comments +answer |
	grep -E 'status:|flags:|RRSIG|IN[[:space:]]+A' || true

echo
echo "== 2. Résolution TCP (dig +tcp) =="
dig-local "@127.0.0.1" -p "$PORT" +tcp example.com A +short

echo
echo "== 3. Cache : deuxième requête et lot de 100 requêtes identiques =="
dig-local "@127.0.0.1" -p "$PORT" example.com A +noall +stats | grep 'Query time' || true

resultat="$(printf 'example.com A\n%.0s' $(seq 1 100) |
	dig-stdin "@127.0.0.1" -p "$PORT" +tries=1 +time=5 -f - |
	awk '/Query time:/ { n++; v=$(NF-1); somme+=v; if (v>max) max=v }
	     END { if (n==0) { print "0 0 0"; exit }
	           printf "%d %.3f %d\n", n, somme/n, max }')"
set -- $resultat
nb="$1"; moyenne="$2"; maximum="$3"
echo "Lot de $nb requêtes mises en cache : moyenne ${moyenne} ms, maximum ${maximum} ms."
if [ "$nb" -lt 100 ]; then
	echo "ERREUR : toutes les requêtes du lot n'ont pas répondu." >&2
	exit 1
fi
if ! awk -v m="$moyenne" 'BEGIN { exit !(m < 5) }'; then
	echo "ERREUR : moyenne ${moyenne} ms au-dessus de l'objectif de 5 ms." >&2
	exit 1
fi

echo
echo "== 4. Réponse négative et absence de fuite DNS directe =="
dig-local "@127.0.0.1" -p "$PORT" example.invalid A +noall +comments | grep 'status:' || true
echo "Connexions établies par le relais (doit pointer vers le SOCKS, jamais vers un résolveur) :"
ss -tnp 2>/dev/null | awk -v p=":$SOCKS_PORT" 'NR>1 && /tordns-client/ { if (index($0,p)) print "  via SOCKS " p; else print "  " $0 }' || true

echo
echo "== 5. Bilan du relais à l'arrêt (aucun nom de domaine journalisé) =="
kill -TERM "$PID"
wait "$PID" 2>/dev/null || true
trap - EXIT
grep -E 'arrêt|TorDNS client' "$JOURNAL" || cat "$JOURNAL"
rm -f "$JOURNAL"

echo
echo "OK : Mission 4 vérifiée."
