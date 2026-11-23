#!/bin/sh
# shellcheck disable=SC1112
# TorDNS — installe un nœud complet sur un Debian 12/13 vierge (Mission 8).
#
#   sudo ./noeud/installer.sh
#   sudo ./noeud/installer.sh --maitresse <adresse oniombalance>   (mission 9)
#
# Idempotent : relancer met le code à jour et redémarre la stack, sans jamais
# toucher aux clés du nœud. Aucun secret n'est généré ici : l'identité du
# service caché est créée par Tor lui-même, dans /var/lib/tordns (0700), et
# n'est envoyée nulle part.
set -eu

PROG=$(basename "$0")
SOURCE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
RACINE=/
UTILISATEUR=tordns
MAITRESSE=
PREFIXE=tordns-noeud
SOUS_RESEAU=172.28.54
SANS_DOCKER=0
SANS_SYSTEMD=0
SANS_ATTENTE=0
SANS_MAJ=0
CLE_MAJ=
REJOINDRE=
IMAGES=${TORDNS_IMAGES:-locale}

usage() {
	cat <<EOF
Usage : sudo ./$PROG [options]

  --maitresse <adresse>  prépare l'instance pour Onionbalance (mission 9) :
                         écrit ob_config et active
                         HiddenServiceOnionbalanceInstance 1
  --utilisateur <nom>    utilisateur système propriétaire du nœud (tordns)
  --prefixe <nom>        préfixe des conteneurs et nom du projet compose
                         (tordns-noeud) ; utile pour plusieurs nœuds sur une
                         même machine de test
  --sous-reseau <a.b.c>  réseau privé du nœud, /24 (172.28.54)
  --racine <dossier>     préfixe d'installation, pour les tests (défaut : /)
  --sans-docker          ne pas installer Docker (déjà fourni par l'hôte)
  --sans-systemd         ne pas activer l'unité systemd (démarrage direct)
  --sans-attente         ne pas attendre la publication du service caché
  --sans-maj             ne pas construire tordns-maj (hors ligne, tests)
  --images <locale|ghcr> images construites localement (défaut) ou tirées de
                         GHCR par empreinte depuis noeud/images.txt
  --cle-maj <hex>        clé publique Ed25519 de publication compilée dans
                         tordns-maj (32 octets en hexadécimal)
  --rejoindre <adresse>  demande l'admission dans le pool communauté via le
                         registre à cette adresse .onion (exige --maitresse
                         avec l'adresse communauté)
  -h, --help             cette aide

Relancer le script est sans danger : le code est mis à jour, les clés et
l'adresse .onion d'instance sont conservées.
EOF
}

die() { printf 'ERREUR : %s\n' "$*" >&2; exit 1; }
info() { printf '== %s\n' "$*"; }
ok() { printf 'OK : %s\n' "$*"; }

while [ $# -gt 0 ]; do
	case $1 in
	--maitresse)
		[ $# -ge 2 ] || die "--maitresse exige une adresse"
		MAITRESSE=$2
		shift 2
		;;
	--utilisateur)
		[ $# -ge 2 ] || die "--utilisateur exige un nom"
		UTILISATEUR=$2
		shift 2
		;;
	--prefixe)
		[ $# -ge 2 ] || die "--prefixe exige un nom"
		PREFIXE=$2
		shift 2
		;;
	--sous-reseau)
		[ $# -ge 2 ] || die "--sous-reseau exige une adresse a.b.c"
		SOUS_RESEAU=$2
		shift 2
		;;
	--racine)
		[ $# -ge 2 ] || die "--racine exige un dossier"
		RACINE=$2
		shift 2
		;;
	--sans-docker) SANS_DOCKER=1; shift ;;
	--sans-systemd) SANS_SYSTEMD=1; shift ;;
	--sans-attente) SANS_ATTENTE=1; shift ;;
	--sans-maj) SANS_MAJ=1; shift ;;
	--images)
		[ $# -ge 2 ] || die "--images exige locale ou ghcr"
		IMAGES=$2
		shift 2
		;;
	--cle-maj)
		[ $# -ge 2 ] || die "--cle-maj exige une clé hexadécimale"
		CLE_MAJ=$2
		shift 2
		;;
	--rejoindre)
		[ $# -ge 2 ] || die "--rejoindre exige une adresse de registre"
		REJOINDRE=$2
		shift 2
		;;
	-h | --help) usage; exit 0 ;;
	*) die "option inconnue : $1 (voir --help)" ;;
	esac
done

# Préfixe : "/" + "/opt/tordns" doit donner "/opt/tordns", pas "//opt/tordns".
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

if [ "$RACINE" = / ] && [ "$(id -u)" -ne 0 ]; then
	die "l'installation dans / exige root : relancez avec sudo"
fi
printf '%s' "$PREFIXE" | grep -Eq '^[a-z0-9][a-z0-9-]{0,40}$' ||
	die "préfixe invalide (minuscules, chiffres et tirets attendus) : $PREFIXE"
printf '%s' "$SOUS_RESEAU" | grep -Eq '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' ||
	die "sous-réseau invalide (a.b.c attendu) : $SOUS_RESEAU"
case $IMAGES in
locale | ghcr) ;;
*) die "--images attend locale ou ghcr : $IMAGES" ;;
esac
[ -f "$SOURCE/docker-compose.yml" ] || die "docker-compose.yml introuvable à côté de $PROG"
[ -f "$SOURCE/../serveur/unbound/unbound.conf" ] || die "dossier serveur/ introuvable : lancez l'installeur depuis un clone du dépôt"
[ -f "$SOURCE/VERSION" ] || die "fichier VERSION introuvable"

# ---------------------------------------------------------------------------
# 1. Système : Debian 12/13 et mémoire
# ---------------------------------------------------------------------------
info "Vérification du système"
OS_RELEASE=$(chemin /etc/os-release)
[ -r "$OS_RELEASE" ] || die "$OS_RELEASE illisible : système non reconnu"
# shellcheck disable=SC1090
. "$OS_RELEASE"
[ "${ID:-}" = debian ] || die "Debian attendu, trouvé : ${ID:-inconnu}"
case ${VERSION_ID:-} in
12 | 13) ok "Debian ${VERSION_ID}" ;;
*) die "Debian 12 ou 13 attendu, trouvé : ${VERSION_ID:-inconnu}" ;;
esac

MEMINFO=$(chemin /proc/meminfo)
if [ -r "$MEMINFO" ]; then
	MEM_KB=$(awk '/^MemTotal:/ {print $2}' "$MEMINFO" 2>/dev/null || echo 0)
	if [ "${MEM_KB:-0}" -lt 950000 ]; then
		printf 'AVERTISSEMENT : %s Mo de RAM, 1 Go conseillé ; la stack est bornée et peut rester lente.\n' "$((MEM_KB / 1024))"
	else
		ok "$((MEM_KB / 1024)) Mo de RAM"
	fi
else
	printf 'AVERTISSEMENT : %s illisible, mémoire non vérifiée.\n' "$MEMINFO"
fi

# ---------------------------------------------------------------------------
# 2. Docker
# ---------------------------------------------------------------------------
if [ "$SANS_DOCKER" -eq 1 ]; then
	command -v docker >/dev/null 2>&1 || die "--sans-docker demandé mais docker est absent"
	docker info >/dev/null 2>&1 || die "--sans-docker demandé mais le démon docker ne répond pas"
	ok "Docker fourni par l'hôte (installation ignorée)"
elif command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
	ok "Docker déjà installé et démarré"
else
	info "Installation de Docker depuis les paquets Debian"
	export DEBIAN_FRONTEND=noninteractive
	apt-get update
	# docker.io fournit le démon et le client ; docker-compose-v2 le greffon
	# `docker compose` (Debian 13). Sur Debian 12, docker-compose (v1) est le
	# repli, d'où la détection ci-dessous.
	apt-get install -y --no-install-recommends docker.io ca-certificates curl
	if ! apt-get install -y --no-install-recommends docker-compose-v2 2>/dev/null; then
		apt-get install -y --no-install-recommends docker-compose ||
			die "aucun outil compose disponible (docker-compose-v2 ou docker-compose)"
	fi
	systemctl enable --now docker
	ok "Docker installé"
fi

# Commande compose complète, utilisée partout (y compris l'unité systemd).
DOCKER_BIN=$(command -v docker)
if "$DOCKER_BIN" compose version >/dev/null 2>&1; then
	COMPOSE="$DOCKER_BIN compose"
elif command -v docker-compose >/dev/null 2>&1; then
	COMPOSE=$(command -v docker-compose)
else
	die "ni 'docker compose' ni 'docker-compose' ne fonctionne"
fi
ok "compose : $COMPOSE"

# ---------------------------------------------------------------------------
# 3. Utilisateur système et dossiers
# ---------------------------------------------------------------------------
info "Utilisateur et dossiers"
if id "$UTILISATEUR" >/dev/null 2>&1; then
	ok "utilisateur $UTILISATEUR déjà présent"
elif [ "$(id -u)" -eq 0 ]; then
	useradd --system --home "$DONNEES" --shell /usr/sbin/nologin "$UTILISATEUR"
	ok "utilisateur système $UTILISATEUR créé"
else
	die "utilisateur $UTILISATEUR absent et création impossible sans root"
fi

mkdir -p "$CODE" "$DONNEES/tor" "$DONNEES/maj"
chmod 0700 "$DONNEES"
# Miroir public /maj/ : lisible par Caddy, jamais modifiable par lui.
chmod 0755 "$DONNEES/maj"

# Propriétaire du dossier Tor : en installation normale, l'utilisateur `tor`
# du conteneur (uid 100, gid 101) ; sans root (tests), l'utilisateur appelant.
if [ "$(id -u)" -eq 0 ] && [ "$RACINE" = / ]; then
	# uid/gid de l'utilisateur `tor` de l'image : le conteneur n'a pas besoin
	# d'être root pour lire son dossier de données.
	TOR_UID=100
	TOR_GID=101
	chown -R "$UTILISATEUR:$UTILISATEUR" "$CODE" "$DONNEES"
	chown "$TOR_UID:$TOR_GID" "$DONNEES/tor"
else
	TOR_UID=$(id -u)
	TOR_GID=$(id -g)
	chown -R "$UTILISATEUR" "$CODE" "$DONNEES" 2>/dev/null || true
fi
chmod 0700 "$DONNEES/tor"
ok "$CODE (code) et $DONNEES (clés, état — 0700)"

# ---------------------------------------------------------------------------
# 4. Code : copie atomique, sans toucher au .env ni aux clés
# ---------------------------------------------------------------------------
info "Installation du code"
TMP_CODE="$CODE/.nouveau.$$"
rm -rf "$TMP_CODE"
mkdir -p "$TMP_CODE"
cp -a "$SOURCE" "$TMP_CODE/noeud"
mkdir -p "$TMP_CODE/serveur"
for dossier in unbound passerelle tor-client; do
	cp -a "$SOURCE/../serveur/$dossier" "$TMP_CODE/serveur/$dossier"
done
cp -a "$SOURCE/../outils" "$TMP_CODE/outils"
rm -rf "$CODE/noeud" "$CODE/serveur" "$CODE/outils"
mv "$TMP_CODE/noeud" "$CODE/noeud"
mv "$TMP_CODE/serveur" "$CODE/serveur"
mv "$TMP_CODE/outils" "$CODE/outils"
rmdir "$TMP_CODE"
VERSION=$(tr -d ' \n\r\t' <"$CODE/noeud/VERSION")
ok "code installé dans $CODE (version $VERSION)"

# ---------------------------------------------------------------------------
# 5. torrc : rendu à chaque exécution, clés jamais touchées
# ---------------------------------------------------------------------------
info "Configuration Tor"
if [ -n "$MAITRESSE" ]; then
	printf '%s' "$MAITRESSE" | grep -Eq '^[a-z2-7]{56}\.onion$' ||
		die "adresse maîtresse invalide (56 caractères base32 + .onion attendus)"
fi

TORRC="$DONNEES/torrc"
{
	cat <<'EOF'
# TorDNS — torrc du nœud, généré par noeud/installer.sh (Mission 8).
# Ne pas modifier à la main : relancer l'installeur.
ClientOnly 1
# Aucun port SOCKS : le nœud ne sert que de service caché.
SocksPort 0
DataDirectory /var/lib/tor

# Port de contrôle en cookie, uniquement sur le réseau docker privé : la page
# d'état y lit « status/circuit-established ». Aucune commande de contrôle
# n'est exposée hors du nœud, aucun journal de requête DNS n'existe.
ControlPort 0.0.0.0:9051
CookieAuthentication 1
CookieAuthFile /var/lib/tor/control_auth_cookie
CookieAuthFileGroupReadable 1

HiddenServiceDir /var/lib/tor/hidden_service
HiddenServiceVersion 3
HiddenServicePort 80 __SOUS_RESEAU__.20:8080
HiddenServiceExportCircuitID haproxy
HiddenServicePoWDefensesEnabled 1
HiddenServiceMaxStreams 64
HiddenServiceMaxStreamsCloseCircuit 1
VanguardsLiteEnabled 1
EOF
	if [ -n "$MAITRESSE" ]; then
		cat <<'EOF'
# Préparation Onionbalance (mission 9) : ce nœud est une instance déclarée
# auprès de l'adresse maîtresse ; ob_config porte MasterOnionAddress.
HiddenServiceOnionbalanceInstance 1
EOF
	fi
	cat <<'EOF'

Log warn stdout
SafeLogging 1
EOF
} | sed "s/__SOUS_RESEAU__/$SOUS_RESEAU/g" >"$TORRC.tmp"
mv "$TORRC.tmp" "$TORRC"
chmod 0644 "$TORRC"

HS="$DONNEES/tor/hidden_service"
mkdir -p "$HS"
chmod 0700 "$HS"
if [ -n "$MAITRESSE" ]; then
	printf 'MasterOnionAddress %s\n' "$MAITRESSE" >"$HS/ob_config"
	chmod 0600 "$HS/ob_config"
	ok "instance Onionbalance préparée pour $MAITRESSE"
else
	rm -f "$HS/ob_config"
	ok "torrc généré (service caché d'instance)"
fi
chown "$TOR_UID:$TOR_GID" "$DONNEES/tor" "$HS" 2>/dev/null || true
[ -f "$HS/ob_config" ] && chown "$TOR_UID:$TOR_GID" "$HS/ob_config" 2>/dev/null || true

# ---------------------------------------------------------------------------
# 6. .env du compose : chemins, version, propriétaire Tor
# ---------------------------------------------------------------------------
info "Fichier d'environnement"
ENV_FILE="$CODE/.env"
if [ ! -f "$ENV_FILE" ]; then
	cat >"$ENV_FILE" <<'EOF'
# TorDNS — réglages du nœud, écrits par noeud/installer.sh.
# Les limites de débit sont modifiables ; relancer l'installeur les conserve.
LIMITE_CIRCUIT_REQ_S=20
LIMITE_CIRCUIT_RAFALE=40
LIMITE_CIRCUITS_MAX=4096
LIMITE_CIRCUIT_TTL=120
LIMITE_REQ_S=200
LIMITE_RAFALE=400
MAX_CONCURRENTS=64
EOF
	chmod 0600 "$ENV_FILE"
fi

definir() {
	cle=$1
	valeur=$2
	tmp="$ENV_FILE.tmp"
	awk -v c="$cle" -v v="$valeur" '
		BEGIN { fait = 0 }
		index($0, c "=") == 1 { print c "=" v; fait = 1; next }
		{ print }
		END { if (!fait) print c "=" v }
	' "$ENV_FILE" >"$tmp"
	mv "$tmp" "$ENV_FILE"
}
definir TORDNS_DONNEES "$DONNEES"
definir TORDNS_VERSION "$VERSION"
definir TORDNS_PROJET "$PREFIXE"
definir TORDNS_PREFIXE "$PREFIXE"
definir TORDNS_SOUS_RESEAU "$SOUS_RESEAU"
definir TORDNS_TOR_UID "$TOR_UID"
definir TORDNS_TOR_GID "$TOR_GID"
definir TORDNS_IMAGES "$IMAGES"
if [ "$IMAGES" = ghcr ]; then
	IMAGES_FICHIER="$CODE/noeud/images.txt"
	[ -f "$IMAGES_FICHIER" ] || die "images.txt absent pour --images ghcr (à côté de noeud/)"
	while IFS='=' read -r slug ref; do
		case $slug in
		serveur-unbound) definir TORDNS_IMAGE_UNBOUND "$ref" ;;
		serveur-passerelle) definir TORDNS_IMAGE_PASSERELLE "$ref" ;;
		noeud-etat) definir TORDNS_IMAGE_ETAT "$ref" ;;
		noeud-tor) definir TORDNS_IMAGE_TOR "$ref" ;;
		serveur-tor-client) definir TORDNS_IMAGE_TOR_CLIENT "$ref" ;;
		esac
	done <"$IMAGES_FICHIER"
	for cle in TORDNS_IMAGE_UNBOUND TORDNS_IMAGE_PASSERELLE TORDNS_IMAGE_ETAT TORDNS_IMAGE_TOR TORDNS_IMAGE_TOR_CLIENT; do
		grep -q "^$cle=." "$ENV_FILE" || die "image $cle absente de $IMAGES_FICHIER"
	done
	ok "images GHCR épinglées par empreinte"
fi
chmod 0600 "$ENV_FILE"
ok "$ENV_FILE"

# ---------------------------------------------------------------------------
# 7. Unités systemd, démarrage
# ---------------------------------------------------------------------------
info "Unité systemd"
UNIT="$UNITES/tordns.service"
mkdir -p "$UNITES"
cat >"$UNIT" <<EOF
[Unit]
Description=TorDNS — nœud DoH via service caché Tor
Documentation=file:$CODE/noeud/README.md
Requires=docker.service
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=$CODE/noeud
ExecStart=$COMPOSE --env-file $ENV_FILE up -d --no-build --remove-orphans
ExecReload=$COMPOSE --env-file $ENV_FILE up -d --no-build --remove-orphans
ExecStop=$COMPOSE --env-file $ENV_FILE down
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 "$UNIT"
ok "$UNIT"

# ---------------------------------------------------------------------------
# 8. Mise à jour signée : binaire tordns-maj, configuration, timer
# ---------------------------------------------------------------------------
info "Mise à jour signée"
ETCDIR=$(chemin /etc/tordns)
mkdir -p "$ETCDIR"
MAJ_ENV="$ETCDIR/maj.env"
SOCKS_MAJ=19050

if [ ! -f "$MAJ_ENV" ]; then
	{
		printf '# TorDNS — mise à jour signée du nœud (Mission 11).\n'
		printf 'TORDNS_MAJ_SOCKS=127.0.0.1:%s\n' "$SOCKS_MAJ"
		printf 'TORDNS_MAJ_SOCKS_PORT=%s\n' "$SOCKS_MAJ"
		printf 'TORDNS_MAJ_ETAT=%s\n' "$DONNEES/maj-etat.json"
		printf 'TORDNS_MAJ_COMPOSE=%s\n' "$CODE/noeud"
		printf 'TORDNS_MAJ_ENV=%s\n' "$ENV_FILE"
		printf 'TORDNS_MAJ_MANIFESTE=\nTORDNS_MAJ_SIGNATURE=\nTORDNS_MAJ_SANTE=\n'
	} >"$MAJ_ENV"
	chmod 0600 "$MAJ_ENV"
fi

definir_maj() {
	cle=$1
	valeur=$2
	tmp="$MAJ_ENV.tmp"
	awk -v c="$cle" -v v="$valeur" '
		BEGIN { fait = 0 }
		index($0, c "=") == 1 { print c "=" v; fait = 1; next }
		{ print }
		END { if (!fait) print c "=" v }
	' "$MAJ_ENV" >"$tmp"
	mv "$tmp" "$MAJ_ENV"
}
if [ -n "$MAITRESSE" ]; then
	definir_maj TORDNS_MAJ_MANIFESTE "http://$MAITRESSE/maj/manifeste.json"
	definir_maj TORDNS_MAJ_SIGNATURE "http://$MAITRESSE/maj/manifeste.json.sig"
	definir_maj TORDNS_MAJ_SANTE "http://$MAITRESSE/healthz"
fi
chmod 0600 "$MAJ_ENV"
chown "$UTILISATEUR" "$MAJ_ENV" 2>/dev/null || true
ok "$MAJ_ENV"

MAJ_UNIT="$UNITES/tordns-maj.service"
cat >"$MAJ_UNIT" <<EOF
[Unit]
Description=TorDNS — mise à jour signée du nœud (par Tor)
Documentation=file:$CODE/noeud/README.md
Requires=docker.service
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
WorkingDirectory=$CODE/noeud
EnvironmentFile=-$MAJ_ENV
ExecStartPre=$COMPOSE --env-file $ENV_FILE --profile maj up -d maj-tor
ExecStart=$BINAIRES/tordns-maj
ExecStopPost=$COMPOSE --env-file $ENV_FILE --profile maj stop maj-tor
TimeoutStartSec=15min
NoNewPrivileges=yes
EOF
chmod 0644 "$MAJ_UNIT"
cp "$CODE/noeud/tordns-maj.timer" "$UNITES/tordns-maj.timer"
chmod 0644 "$UNITES/tordns-maj.timer"
ok "$MAJ_UNIT et timer"

MAJ_BUILT=0
if [ "$SANS_MAJ" -eq 1 ] || [ "$RACINE" != / ]; then
	ok "tordns-maj non construit (--sans-maj ou installation de test)"
else
	printf '%s' "$CLE_MAJ" | grep -Eq '^([0-9a-f]{64})$' ||
		printf 'AVERTISSEMENT : --cle-maj absente ou invalide ; les mises à jour seront refusées tant que la clé de Gary ne sera pas compilée.\n'
	JOURNAL_MAJ="$DONNEES/maj-construction.log"
	if docker run --rm -e CGO_ENABLED=0 -v "$CODE":/src -w /src/noeud/maj \
		golang:1.23-alpine go build -trimpath \
		-ldflags "-s -w -X tordns/manifeste.ClePubliqueEpinglee=$CLE_MAJ" \
		-o /src/tordns-maj . >"$JOURNAL_MAJ" 2>&1; then
		install -m 0755 "$CODE/tordns-maj" "$BINAIRES/tordns-maj"
		rm -f "$CODE/tordns-maj" "$JOURNAL_MAJ"
		MAJ_BUILT=1
		ok "tordns-maj installé dans $BINAIRES"
	else
		tail -n 5 "$JOURNAL_MAJ" >&2 || true
		printf 'AVERTISSEMENT : construction de tordns-maj impossible ; mises à jour désactivées.\n'
	fi
fi

construire() {
	if [ "$IMAGES" = ghcr ]; then
		# Aucune construction : les empreintes de images.txt désignent les
		# images multi-arch publiées par la release.
		# shellcheck disable=SC2086
		(cd "$CODE/noeud" && $COMPOSE --env-file "$ENV_FILE" pull --quiet)
		return
	fi
	# Reconstruit les images à partir du code copié : une mise à jour du dépôt
	# doit changer le comportement du nœud, pas seulement ses conteneurs.
	# shellcheck disable=SC2086
	(cd "$CODE/noeud" && $COMPOSE --env-file "$ENV_FILE" build --quiet)
}

demarrer() {
	# shellcheck disable=SC2086
	(cd "$CODE/noeud" && $COMPOSE --env-file "$ENV_FILE" up -d --no-build --remove-orphans)
}
info "Images : $IMAGES"
construire

if [ "$SANS_SYSTEMD" -eq 1 ] || [ "$RACINE" != / ]; then
	info "Démarrage direct de la stack (systemd non activé)"
	demarrer
else
	systemctl daemon-reload
	systemctl enable --now tordns.service
	ok "tordns.service activé"
	if [ "$MAJ_BUILT" -eq 1 ] && grep -q '^TORDNS_MAJ_MANIFESTE=..*' "$MAJ_ENV"; then
		systemctl enable --now tordns-maj.timer
		ok "tordns-maj.timer activé (toutes les 6 h)"
	else
		ok "timer de mise à jour non activé (clé ou URL de manifeste absente)"
	fi
fi

# ---------------------------------------------------------------------------
# 8. Commande d'adresse et attente de publication
# ---------------------------------------------------------------------------
ADRESSE_SH="$BINAIRES/tordns-adresse"
mkdir -p "$BINAIRES"
cat >"$ADRESSE_SH" <<EOF
#!/bin/sh
# TorDNS — affiche l'adresse .onion d'instance du nœud.
fichier='$DONNEES/tor/hidden_service/hostname'
if [ -s "\$fichier" ]; then
	cat "\$fichier"
else
	cd '$CODE/noeud' || exit 1
	$COMPOSE --env-file '$ENV_FILE' exec -T tor cat /var/lib/tor/hidden_service/hostname
fi
EOF
chmod 0755 "$ADRESSE_SH"

HOSTNAME_FILE="$DONNEES/tor/hidden_service/hostname"
if [ "$SANS_ATTENTE" -eq 0 ]; then
	info "Attente de la publication du service caché (max 180 s)"
	i=0
	while [ ! -s "$HOSTNAME_FILE" ]; do
		i=$((i + 1))
		if [ "$i" -gt 90 ]; then
			die "le service caché n'est pas publié après 180 s : voir '$COMPOSE logs tor' dans $CODE/noeud"
		fi
		sleep 2
	done
fi

echo
if [ -s "$HOSTNAME_FILE" ]; then
	ADRESSE=$(cat "$HOSTNAME_FILE")
	printf 'Adresse .onion d’instance : %s\n' "$ADRESSE"
else
	printf 'Adresse pas encore publiée.\n'
fi

# ---------------------------------------------------------------------------
# 9. Inscription au registre communautaire (Mission 10)
# ---------------------------------------------------------------------------
if [ -n "$REJOINDRE" ]; then
	info "Inscription au registre communautaire"
	[ -n "$MAITRESSE" ] || die "--rejoindre exige --maitresse <adresse communauté> (ob_config du nœud)"
	[ -s "$HOSTNAME_FILE" ] || die "adresse d'instance inconnue : inscription impossible"

	JOURNAL_INSC="$DONNEES/inscription-construction.log"
	if ! docker run --rm -e CGO_ENABLED=0 -v "$CODE":/src -w /src/outils/inscription \
		golang:1.23-alpine go build -trimpath -ldflags "-s -w" \
		-o /src/tordns-inscrire . >"$JOURNAL_INSC" 2>&1; then
		tail -n 5 "$JOURNAL_INSC" >&2 || true
		die "construction de tordns-inscrire impossible"
	fi
	install -m 0755 "$CODE/tordns-inscrire" "$BINAIRES/tordns-inscrire"
	rm -f "$CODE/tordns-inscrire" "$JOURNAL_INSC"
	ok "tordns-inscrire installé dans $BINAIRES"

	# Un client Tor séparé fournit le SOCKS loopback utilisé seulement le temps
	# de l'inscription ; il est arrêté ensuite.
	# shellcheck disable=SC2086
	(cd "$CODE/noeud" && $COMPOSE --env-file "$ENV_FILE" --profile maj up -d maj-tor)
	DEFI="$DONNEES/tor/defi"
	REGISTRE_URL=$REJOINDRE
	case "$REGISTRE_URL" in
	http://* | https://*) ;;
	*) REGISTRE_URL="http://$REGISTRE_URL" ;;
	esac
	i=0
	until "$BINAIRES/tordns-inscrire" -registre "$REGISTRE_URL" \
		-adresse "$(cat "$HOSTNAME_FILE")" -defi "$DEFI" \
		-socks "127.0.0.1:$SOCKS_MAJ"; do
		i=$((i + 1))
		[ "$i" -lt 8 ] || die "inscription au registre impossible (voir ci-dessus)"
		printf 'Nouvel essai dans 5 s (%s/8)…\n' "$i"
		sleep 5
	done
	chmod 0644 "$DEFI" 2>/dev/null || true
	chown "$TOR_UID:$TOR_GID" "$DEFI" 2>/dev/null || true
	# shellcheck disable=SC2086
	(cd "$CODE/noeud" && $COMPOSE --env-file "$ENV_FILE" --profile maj stop maj-tor) >/dev/null 2>&1 || true
	ok "inscription envoyée ; admission seulement après la quarantaine de sondes"
fi
cat <<EOF

Pour retrouver cette adresse plus tard :
    tordns-adresse

Page d'état : http://<adresse>.onion/.well-known/tordns/etat
Code       : $CODE
Clés, état : $DONNEES (0700 — à sauvegarder, jamais dans git)
Désinstaller : sudo ./noeud/desinstaller.sh
EOF
