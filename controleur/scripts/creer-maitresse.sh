#!/bin/sh
# TorDNS — crée la clé maîtresse d'Onionbalance (Mission 9).
#
#   sudo ./controleur/scripts/creer-maitresse.sh
#   sudo ./controleur/scripts/creer-maitresse.sh --nom communaute   (mission 10)
#   ./controleur/scripts/creer-maitresse.sh --donnees /chemin/jetable   (tests)
#
# Deux identités distinctes : `maitresse` (pool cœur) et `communaute` (pool
# des bénévoles admis). Elles ne partagent jamais leur clé.
#
# Idempotent : si la clé existe, le script affiche seulement l'adresse et ne
# touche à rien. La clé est la seule chose qui fait l'identité publique du
# service : elle ne doit jamais entrer dans git ni être copiée en clair.
# La sauvegarde chiffrée est décrite dans docs/redondance.md.
set -eu

BASE=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
DONNEES=${TORDNS_CONTROLEUR_DONNEES:-/var/lib/tordns-controleur}
NOM=maitresse

usage() {
	cat <<EOF
Usage : sudo ./controleur/scripts/creer-maitresse.sh [--donnees <dossier>] [--nom <identité>]

  --donnees <dossier>  dossier des secrets du contrôleur
                       (défaut : /var/lib/tordns-controleur, 0700)
  --nom <identité>     maitresse (défaut, pool cœur) ou communaute
  -h, --help           cette aide
EOF
}

die() { printf 'ERREUR : %s\n' "$*" >&2; exit 1; }
info() { printf '== %s\n' "$*"; }
ok() { printf 'OK : %s\n' "$*"; }

while [ $# -gt 0 ]; do
	case $1 in
	--donnees)
		[ $# -ge 2 ] || die "--donnees exige un dossier"
		DONNEES=$2
		shift 2
		;;
	--nom)
		[ $# -ge 2 ] || die "--nom exige maitresse ou communaute"
		NOM=$2
		shift 2
		;;
	-h | --help) usage; exit 0 ;;
	*) die "option inconnue : $1 (voir --help)" ;;
	esac
done

if [ "$DONNEES" = /var/lib/tordns-controleur ] && [ "$(id -u)" -ne 0 ]; then
	die "le dossier par défaut exige root : relancez avec sudo, ou utilisez --donnees"
fi
command -v docker >/dev/null 2>&1 || die "docker est absent"
docker info >/dev/null 2>&1 || die "le démon docker ne répond pas"

# Même uid/gid que le Tor du contrôleur : onionbalance lit la clé et le cookie
# sans privilège supplémentaire. En test sans root, l'utilisateur appelant.
if [ "$(id -u)" -eq 0 ]; then
	UID_=100
	GID_=101
else
	UID_=$(id -u)
	GID_=$(id -g)
fi

mkdir -p "$DONNEES/tor" "$DONNEES/registre" "$DONNEES/pools"
chmod 0700 "$DONNEES" "$DONNEES/tor" "$DONNEES/registre" "$DONNEES/pools"
chown "$UID_:$GID_" "$DONNEES" "$DONNEES/tor" "$DONNEES/registre" "$DONNEES/pools" 2>/dev/null || true

ENV_FILE="$DONNEES/.env"
cat >"$ENV_FILE" <<EOF
# TorDNS — contrôleur Onionbalance, écrit par creer-maitresse.sh.
TORDNS_CONTROLEUR_DONNEES=$DONNEES
TORDNS_CONTROLEUR_UID=$UID_
TORDNS_CONTROLEUR_GID=$GID_
EOF
chmod 0600 "$ENV_FILE"

case "$NOM" in
maitresse | communaute) ;;
*) die "--nom doit être maitresse ou communaute" ;;
esac
CLE="$DONNEES/$NOM.key"
FICHIER_ADRESSE="$DONNEES/$NOM.onion"

if [ -s "$CLE" ] && [ -s "$FICHIER_ADRESSE" ]; then
	ok "clé $NOM déjà présente, inchangée"
	printf 'Adresse %s : %s\n' "$NOM" "$(cat "$FICHIER_ADRESSE")"
	exit 0
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
compose() { (cd "$BASE" && $COMPOSE --env-file "$ENV_FILE" -f docker-compose.yml "$@"); }

info "Construction de l'image onionbalance"
compose build onionbalance

info "Génération de la clé maîtresse"
TMP_GEN="$DONNEES/.gen.$$"
rm -rf "$TMP_GEN"
mkdir -p "$TMP_GEN"
chmod 0700 "$TMP_GEN"
if ! docker run --rm -v "$TMP_GEN:/gen" \
	--entrypoint onionbalance-config tordns/onionbalance:local \
	--hs-version v3 -n 1 --output /gen >/dev/null; then
	rm -rf "$TMP_GEN"
	die "onionbalance-config a échoué"
fi
# Le conteneur écrit en root : rendre les fichiers lisibles par le compte du
# contrôleur avant de les déplacer depuis l'hôte.
docker run --rm --user 0 -v "$TMP_GEN:/gen" \
	--entrypoint chown tordns/onionbalance:local -R "$UID_:$GID_" /gen

CLE_GEN=$(find "$TMP_GEN" -maxdepth 1 -name '*.key' -type f | head -n 1)
[ -n "$CLE_GEN" ] || { rm -rf "$TMP_GEN"; die "aucune clé générée"; }
# onionbalance-config nomme la clé <adresse>.key, sans le suffixe .onion.
ADRESSE=$(basename "$CLE_GEN" .key)
printf '%s' "$ADRESSE" | grep -Eq '^[a-z2-7]{56}$' || {
	rm -rf "$TMP_GEN"
	die "adresse générée invalide : $ADRESSE"
}
ADRESSE="$ADRESSE.onion"

mv "$CLE_GEN" "$CLE"
printf '%s\n' "$ADRESSE" >"$FICHIER_ADRESSE"
chmod 0600 "$CLE" "$FICHIER_ADRESSE"
chown "$UID_:$GID_" "$CLE" "$FICHIER_ADRESSE" 2>/dev/null || true
rm -rf "$TMP_GEN"

ok "clé $NOM créée dans $CLE (0600, hors dépôt)"
printf 'Adresse %s : %s\n' "$NOM" "$ADRESSE"
cat <<EOF

Sauvegarde : la perte de cette clé perd l'identité publique du service.
    Voir la procédure chiffrée (age ou GPG) dans docs/redondance.md.
Étape suivante :
    cp controleur/pools/coeur.txt.example controleur/pools/coeur.txt
    \$EDITOR controleur/pools/coeur.txt     # une adresse d'instance par ligne
    sudo ./controleur/scripts/demarrer.sh
EOF
