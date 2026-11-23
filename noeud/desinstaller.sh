#!/bin/sh
# shellcheck disable=SC1112
# TorDNS — désinstallation du nœud (Mission 8).
#
# Retire le service, les conteneurs, le code et la commande d'adresse.
# Les clés et l'état de /var/lib/tordns sont CONSERVÉS : une réinstallation
# retrouve la même adresse .onion. Leur suppression exige --supprimer-cles et
# une confirmation tapée.
set -eu

PROG=$(basename "$0")
RACINE=/
SUPPRIMER_CLES=0
SANS_SYSTEMD=0

usage() {
	cat <<EOF
Usage : sudo ./$PROG [options]

  --supprimer-cles  supprime aussi /var/lib/tordns (clés du nœud) après
                    confirmation tapée « SUPPRIMER »
  --racine <dossier> préfixe d'installation, pour les tests (défaut : /)
  --sans-systemd    ne pas toucher systemd (démarrage direct)
  -h, --help        cette aide
EOF
}

die() { printf 'ERREUR : %s\n' "$*" >&2; exit 1; }
info() { printf '== %s\n' "$*"; }
ok() { printf 'OK : %s\n' "$*"; }

while [ $# -gt 0 ]; do
	case $1 in
	--supprimer-cles) SUPPRIMER_CLES=1; shift ;;
	--racine)
		[ $# -ge 2 ] || die "--racine exige un dossier"
		RACINE=$2
		shift 2
		;;
	--sans-systemd) SANS_SYSTEMD=1; shift ;;
	-h | --help) usage; exit 0 ;;
	*) die "option inconnue : $1 (voir --help)" ;;
	esac
done

case $RACINE in
*/) RACINE=${RACINE%/} ;;
esac
[ -n "$RACINE" ] || RACINE=/

chemin() {
	if [ "$RACINE" = / ]; then
		printf '%s' "$1"
	else
		printf '%s%s' "$RACINE" "$1"
	fi
}

CODE=$(chemin /opt/tordns)
DONNEES=$(chemin /var/lib/tordns)
UNITES=$(chemin /etc/systemd/system)
BINAIRES=$(chemin /usr/local/bin)
ETCDIR=$(chemin /etc/tordns)
ENV_FILE="$CODE/.env"
MAJ_ENV="$ETCDIR/maj.env"

if [ "$RACINE" = / ] && [ "$(id -u)" -ne 0 ]; then
	die "la désinstallation depuis / exige root : relancez avec sudo"
fi
if [ ! -d "$CODE" ] && [ ! -d "$DONNEES" ]; then
	die "aucune installation TorDNS trouvée ($CODE et $DONNEES absents)"
fi

# ---------------------------------------------------------------------------
# 1. Service et conteneurs
# ---------------------------------------------------------------------------
if [ "$SANS_SYSTEMD" -eq 0 ] && [ "$RACINE" = / ]; then
	info "Arrêt du service"
	if systemctl list-unit-files tordns.service >/dev/null 2>&1; then
		systemctl disable --now tordns.service 2>/dev/null || true
	fi
	if systemctl list-unit-files tordns-maj.timer >/dev/null 2>&1; then
		systemctl disable --now tordns-maj.timer tordns-maj.service 2>/dev/null || true
	fi
fi

if [ -d "$CODE/noeud" ]; then
	info "Arrêt de la stack"
	DOCKER_BIN=$(command -v docker 2>/dev/null || true)
	COMPOSE=
	if [ -n "$DOCKER_BIN" ] && "$DOCKER_BIN" compose version >/dev/null 2>&1; then
		COMPOSE="$DOCKER_BIN compose"
	elif command -v docker-compose >/dev/null 2>&1; then
		COMPOSE=$(command -v docker-compose)
	fi
	if [ -n "$COMPOSE" ]; then
		# shellcheck disable=SC2086
		# --profile test : le client Tor de test, s'il tourne, tient aussi aux
		# réseaux du nœud et doit être retiré.
		(cd "$CODE/noeud" && $COMPOSE --env-file "$ENV_FILE" --profile test --profile maj down --remove-orphans) ||
			printf 'AVERTISSEMENT : la stack ne s’est pas arrêtée proprement.\n'
		for image in tordns/noeud-tor:local tordns/etat:local; do
			"$DOCKER_BIN" image rm "$image" >/dev/null 2>&1 || true
		done
		ok "conteneurs et images du nœud retirés"
	else
		printf 'AVERTISSEMENT : docker compose absent, conteneurs non arrêtés.\n'
	fi
fi

# ---------------------------------------------------------------------------
# 2. Fichiers du programme
# ---------------------------------------------------------------------------
info "Suppression du code et de l'unité"
rm -f "$UNITES/tordns.service" "$UNITES/tordns-maj.service" "$UNITES/tordns-maj.timer"
if [ "$RACINE" = / ] && [ "$SANS_SYSTEMD" -eq 0 ]; then
	systemctl daemon-reload 2>/dev/null || true
fi
rm -f "$BINAIRES/tordns-adresse" "$BINAIRES/tordns-maj"
rm -rf "$CODE"
rm -f "$MAJ_ENV"
ok "code, unité et commande tordns-adresse supprimés"

# ---------------------------------------------------------------------------
# 3. Clés : conservées par défaut, jamais supprimées sans confirmation tapée
# ---------------------------------------------------------------------------
if [ "$SUPPRIMER_CLES" -eq 1 ]; then
	printf '\nLes clés et l’état de %s vont être DÉFINITIVEMENT supprimés.\n' "$DONNEES"
	printf 'L’adresse .onion d’instance sera perdue.\n'
	printf 'Tapez SUPPRIMER pour confirmer : '
	reponse=
	read -r reponse || true
	if [ "$reponse" != SUPPRIMER ]; then
		printf 'Confirmation incorrecte : clés conservées dans %s\n' "$DONNEES"
		exit 1
	fi
	rm -rf "$DONNEES"
	ok "clés et état supprimés ($DONNEES)"
else
	ok "clés et état conservés dans $DONNEES"
	cat <<EOF

L’adresse .onion d’instance reste disponible pour une réinstallation.
Pour effacer aussi les clés (irréversible) :
    sudo ./$PROG --supprimer-cles

La page d'état et le service sont arrêtés ; aucun conteneur TorDNS du nœud
ne tourne plus. Un autre nœud du même hôte n'est pas touché.
EOF
fi
