#!/bin/sh
# TorDNS — applique le pool communauté au second Onionbalance (Mission 10).
#
#   sudo ./controleur/scripts/recharger-communaute.sh
#
# Le registre écrit $DONNEES/pools/communaute.txt sans jamais toucher au pool
# cœur. Ce script régénère la configuration et ne redémarre Onionbalance que
# si elle a changé. Il est prévu pour un timer systemd de deux minutes : une
# admission ou une éviction est donc publiée en au plus deux minutes.
set -eu

BASE=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
DONNEES=${TORDNS_CONTROLEUR_DONNEES:-/var/lib/tordns-controleur}
POOL="$DONNEES/pools/communaute.txt"
CLE=/donnees/communaute.key
SORTIE="$DONNEES/config-communaute.yaml"

die() { printf 'ERREUR : %s\n' "$*" >&2; exit 1; }
ok() { printf 'OK : %s\n' "$*"; }

[ -s "$DONNEES/communaute.key" ] || die "clé communauté absente : creer-maitresse.sh --nom communaute"
[ -s "$POOL" ] || die "pool communauté absent : le registre n'a encore admis aucun nœud"
# Un pool vide ne peut pas être publié : on conserve la dernière configuration
# valide plutôt que de couper l'adresse communauté.
if ! grep -Eq '^[a-z2-7]{56}\.onion$' "$POOL"; then
	ok "pool communauté vide, configuration inchangée"
	exit 0
fi

TMP="$SORTIE.nouveau.$$"
trap 'rm -f "$TMP"' EXIT
"$BASE/scripts/generer-config.sh" --pool "$POOL" --donnees "$DONNEES" \
	--cle "$CLE" --sortie "$TMP" >/dev/null
if [ -f "$SORTIE" ] && cmp -s "$TMP" "$SORTIE"; then
	ok "configuration communauté inchangée"
	exit 0
fi
chmod 0600 "$TMP"
mv "$TMP" "$SORTIE"
trap - EXIT

DOCKER_BIN=$(command -v docker)
if "$DOCKER_BIN" compose version >/dev/null 2>&1; then
	COMPOSE="$DOCKER_BIN compose"
elif command -v docker-compose >/dev/null 2>&1; then
	COMPOSE=$(command -v docker-compose)
else
	die "ni 'docker compose' ni 'docker-compose' ne fonctionne"
fi
# shellcheck disable=SC2086
(cd "$BASE" && $COMPOSE --env-file "$DONNEES/.env" -f docker-compose.yml \
	--profile communaute up -d --no-deps --force-recreate onionbalance-communaute)
ok "adresse communauté rechargée"
