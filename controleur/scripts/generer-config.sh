#!/bin/sh
# shellcheck disable=SC1112
# TorDNS — génère le config.yaml d'Onionbalance depuis le pool d'instances
# (Mission 9). Le pool est un fichier texte hors dépôt : une adresse .onion
# d'instance par ligne, lignes vides et commentaires (#) ignorés.
#
#   ./controleur/scripts/generer-config.sh --pool controleur/pools/coeur.txt
#
# La configuration générée ne contient aucun secret : seulement les adresses
# publiques des instances et le chemin de la clé maîtresse dans le conteneur.
set -eu

BASE=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
DONNEES=${TORDNS_CONTROLEUR_DONNEES:-/var/lib/tordns-controleur}
POOL="$BASE/pools/coeur.txt"
STATUS_SOCKET=
# Chemin de la clé dans le conteneur Onionbalance (jamais sur l'hôte en clair
# dans la configuration).
CLE=/donnees/maitresse.key
# Renseigné après l'analyse des options : --donnees peut changer le défaut.
SORTIE=

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
	--sortie)
		[ $# -ge 2 ] || die "--sortie exige un fichier"
		SORTIE=$2
		shift 2
		;;
	--cle)
		[ $# -ge 2 ] || die "--cle exige un chemin de clé (dans le conteneur)"
		CLE=$2
		shift 2
		;;
	--status-socket)
		[ $# -ge 2 ] || die "--status-socket exige un chemin"
		STATUS_SOCKET=$2
		shift 2
		;;
	-h | --help)
		printf 'Usage : %s [--pool fichier] [--donnees dossier] [--sortie fichier] [--status-socket chemin]\n' "$0"
		exit 0
		;;
	*) die "option inconnue : $1" ;;
	esac
done

[ -n "$SORTIE" ] || SORTIE="$DONNEES/config.yaml"
[ -r "$POOL" ] || die "pool illisible : $POOL (copier coeur.txt.example)"
CLE_HOTE=$CLE
case "$CLE_HOTE" in
/donnees/*) CLE_HOTE="$DONNEES/${CLE_HOTE#/donnees/}" ;;
esac
[ -s "$CLE_HOTE" ] || die "clé absente : $CLE_HOTE (lancer creer-maitresse.sh --nom …)"

TMP="$SORTIE.tmp.$$"
trap 'rm -f "$TMP"' EXIT
{
	printf '# TorDNS — configuration Onionbalance générée depuis %s.\n' "$POOL"
	printf '# Ne pas modifier à la main : éditer le pool puis relancer demarrer.sh.\n'
	if [ -n "$STATUS_SOCKET" ]; then
		printf 'status-socket-location: %s\n' "$STATUS_SOCKET"
	fi
	printf 'services:\n'
	printf '  - key: %s\n' "$CLE"
	printf '    instances:\n'
} >"$TMP"

NOMBRE=0
while IFS= read -r ligne || [ -n "$ligne" ]; do
	# Retire commentaire et espaces autour de l'adresse.
	ligne=$(printf '%s' "$ligne" | sed 's/#.*//; s/[[:space:]]//g')
	[ -n "$ligne" ] || continue
	printf '%s' "$ligne" | grep -Eq '^[a-z2-7]{56}\.onion$' || {
		die "adresse d'instance invalide dans $POOL : $ligne"
	}
	NOMBRE=$((NOMBRE + 1))
	printf '      - address: %s\n        name: noeud-%s\n' "$ligne" "$NOMBRE" >>"$TMP"
done <"$POOL"

[ "$NOMBRE" -ge 1 ] || die "le pool $POOL ne contient aucune instance"
# Onionbalance prend 2 points d'introduction par instance ; le protocole v3
# en admet 20 par descripteur, soit 10 instances au plus. Au-delà, la
# publication du descripteur maître échouera : on prévient sans bloquer, la
# limite réelle se mesure sur le réseau.
if [ "$NOMBRE" -gt 10 ]; then
	printf 'AVERTISSEMENT : %s instances ; au-delà de 10 (20 points d’introduction / 2 par instance), le descripteur maître risque d’être refusé.\n' "$NOMBRE" >&2
fi

chmod 0600 "$TMP"
mv "$TMP" "$SORTIE"
trap - EXIT
ok "config.yaml généré ($NOMBRE instance(s)) : $SORTIE"
