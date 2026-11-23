#!/bin/sh
# TorDNS — démarre (ou met à jour) le contrôleur Onionbalance (Mission 9).
#
#   sudo ./controleur/scripts/demarrer.sh
#   ./controleur/scripts/demarrer.sh --pool controleur/pools/coeur.txt
#
# Régénère config.yaml depuis le pool puis (re)lance les conteneurs. Ajouter ou
# retirer un nœud : éditer le pool, relancer ce script.
set -eu

BASE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
DONNEES=${TORDNS_CONTROLEUR_DONNEES:-/var/lib/tordns-controleur}
POOL="$BASE/pools/coeur.txt"

die() { printf 'ERREUR : %s\n' "$*" >&2; exit 1; }
ok() { printf 'OK : %s\n' "$*"; }

while [ $# -gt 0 ]; do
	case $1 in
	--pool)
		[ $# -ge 2 ] || die "--pool exige un fichier"
		POOL=$2
		shift 2
		;;
	--donnees)
		[ $# -ge 2 ] || die "--donnees exige un dossier"
		DONNEES=$2
		shift 2
		;;
	-h | --help)
		printf 'Usage : %s [--pool fichier] [--donnees dossier]\n' "$0"
		exit 0
		;;
	*) die "option inconnue : $1" ;;
	esac
done

ENV_FILE="$DONNEES/.env"
[ -f "$ENV_FILE" ] || die "contrôleur non initialisé : lancer creer-maitresse.sh"
[ -s "$DONNEES/maitresse.key" ] || die "clé maîtresse absente : lancer creer-maitresse.sh"

"$BASE/scripts/generer-config.sh" --pool "$POOL" --donnees "$DONNEES"

# Pool communauté (Mission 10) : activé seulement quand la clé et un premier
# pool existent. Le registre et son service caché démarrent dans tous les cas.
PROFIL=
if [ -s "$DONNEES/communaute.key" ] && [ -s "$DONNEES/pools/communaute.txt" ] &&
	grep -Eq '^[a-z2-7]{56}\.onion$' "$DONNEES/pools/communaute.txt"; then
	"$BASE/scripts/generer-config.sh" --pool "$DONNEES/pools/communaute.txt" \
		--donnees "$DONNEES" --cle /donnees/communaute.key \
		--sortie "$DONNEES/config-communaute.yaml"
	PROFIL="--profile communaute"
fi

DOCKER_BIN=$(command -v docker)
if "$DOCKER_BIN" compose version >/dev/null 2>&1; then
	COMPOSE="$DOCKER_BIN compose"
elif command -v docker-compose >/dev/null 2>&1; then
	COMPOSE=$(command -v docker-compose)
else
	die "ni 'docker compose' ni 'docker-compose' ne fonctionne"
fi
# shellcheck disable=SC2086
# shellcheck disable=SC2086
(cd "$BASE" && $COMPOSE --env-file "$ENV_FILE" -f docker-compose.yml $PROFIL up -d --build --remove-orphans)

ok "contrôleur démarré"
printf 'Adresse maîtresse : %s\n' "$(cat "$DONNEES/maitresse.onion")"
cat <<EOF

Le descripteur maître n'est publié qu'après récupération des descripteurs des
instances : compter jusqu'à une dizaine de minutes au premier démarrage.
Journaux : sudo docker logs tordns-controleur-onionbalance
Arrêt    : sudo docker compose --env-file $ENV_FILE -f $BASE/docker-compose.yml down
EOF
