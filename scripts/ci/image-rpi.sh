#!/usr/bin/env bash
# TorDNS — image nœud pour Raspberry Pi (Mission 24).
#
# Part de Raspberry Pi OS Lite 64 bits officiel (téléchargé, SHA-256 épinglé),
# et le modifie **sans privilèges** : les deux partitions sont extraites dans
# des fichiers, éditées avec mtools et debugfs dans un conteneur non privilégié,
# puis réinsérées. Aucun montage en boucle, aucun systemd-nspawn, aucun accès
# root sur la machine qui construit.
#
# L'image contient : Docker en binaires statiques, le code du nœud dans
# /opt/tordns, les outils du premier démarrage, la page d'état locale et les
# unités systemd. Elle ne contient **ni clé .onion, ni mot de passe, ni accès
# SSH** : les clés naissent sur la carte au premier démarrage.
set -euo pipefail

RACINE=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
VERSION=${VERSION:-$("$RACINE/scripts/ci/version.sh")}

RPI_DATE=2026-10-06
RPI_FICHIER="${RPI_DATE}-raspios-trixie-arm64-lite.img.xz"
RPI_URL="https://downloads.raspberrypi.com/raspios_lite_arm64/images/raspios_lite_arm64-${RPI_DATE}/${RPI_FICHIER}"
RPI_SHA=483db18a48da399b5b7022ffae9a07bc6d99daab30e593aedac09b69ff422843

DOCKER_VERSION=29.10.0
DOCKER_FICHIER="docker-${DOCKER_VERSION}.tgz"
DOCKER_URL="https://download.docker.com/linux/static/stable/aarch64/${DOCKER_FICHIER}"
DOCKER_SHA=6e5159e8b5615e0c0c2954a2a1a2a12bc65f5d9b603595dba24a10cb367408cd

CACHE=${RPI_CACHE:-"$RACINE/dist/rpi/cache"}
DIST=${DIST:-"$RACINE/dist/rpi"}
IMAGE_OUTILS=tordns-rpi-outils
TMP=$(mktemp -d "${TMPDIR:-/tmp}/tordns-rpi.XXXXXX")
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$CACHE" "$DIST"
export GOTOOLCHAIN=${GOTOOLCHAIN:-go1.23.7}

section() { printf '\n== %s ==\n' "$*"; }
ok() { printf 'OK : %s\n' "$*"; }
info() { printf '%s\n' "$*"; }
echec() { printf 'ÉCHEC : %s\n' "$*" >&2; exit 1; }

docker info >/dev/null 2>&1 || echec "docker indisponible : la construction se fait dans un conteneur non privilégié"
docker build -q -t "$IMAGE_OUTILS" -f "$RACINE/scripts/ci/rpi-outils.Dockerfile" "$RACINE/scripts/ci" \
	>/dev/null || echec "construction de l'image d'outils"
conteneur() {
	docker run --rm --user "$(id -u):$(id -g)" -v "$DIST":/w -v "$TMP":/t \
		-w /w "$IMAGE_OUTILS" sh -c "$1"
}

# ---------------------------------------------------------------------------
section "1. Binaires Go pour arm64"
BINAIRES=$TMP/binaires
mkdir -p "$BINAIRES"
construire() {
	local dossier=$1 nom=$2
	shift 2
	(cd "$RACINE/$dossier" && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 \
		go build -buildvcs=false -trimpath -ldflags "-s -w -buildid=" -o "$BINAIRES/$nom" .) ||
		echec "compilation de $nom"
	[ -s "$BINAIRES/$nom" ] || echec "binaire vide : $nom"
	file "$BINAIRES/$nom" | grep -q 'ARM aarch64' || echec "$nom n'est pas un binaire arm64"
	info "$(printf '%-22s %s octets' "$nom" "$(stat -c '%s' "$BINAIRES/$nom")")"
}
construire noeud/raspberry/cles-onion tordns-cles-onion
construire noeud/raspberry/etat-local tordns-etat-local
construire outils/inscription tordns-inscription
ok "trois binaires statiques arm64"

# ---------------------------------------------------------------------------
section "2. Téléchargements vérifiés"
telecharger() {
	local url=$1 fichier=$2 sha=$3
	if [ ! -f "$CACHE/$fichier" ]; then
		info "téléchargement de $fichier"
		curl -fsSL --retry 3 -o "$CACHE/$fichier.partiel" "$url" ||
			echec "téléchargement de $url"
		mv "$CACHE/$fichier.partiel" "$CACHE/$fichier"
	fi
	printf '%s  %s\n' "$sha" "$CACHE/$fichier" | sha256sum -c --status - ||
		echec "SHA-256 de $fichier incorrect"
	ok "$fichier (SHA-256 épinglé)"
}
telecharger "$RPI_URL" "$RPI_FICHIER" "$RPI_SHA"
telecharger "$DOCKER_URL" "$DOCKER_FICHIER" "$DOCKER_SHA"

# ---------------------------------------------------------------------------
section "3. Image de travail"
TRAVAIL=$TMP/image
mkdir -p "$TRAVAIL"
tar xzf "$CACHE/$DOCKER_FICHIER" -C "$TRAVAIL"
mv "$TRAVAIL/docker" "$TRAVAIL/docker-binaires"
xz -dc "$CACHE/$RPI_FICHIER" >"$TRAVAIL/base.img"
python3 "$RACINE/scripts/ci/rpi-partitions.py" extraire \
	"$TRAVAIL/base.img" "$TRAVAIL/boot.fat" "$TRAVAIL/racine.ext4"
ok "partitions extraites : $(stat -c '%s' "$TRAVAIL/boot.fat") et $(stat -c '%s' "$TRAVAIL/racine.ext4") octets"

# ---------------------------------------------------------------------------
section "4. Arbre de fichiers de l'image"
ARBRE=$TRAVAIL/arbre
mkdir -p "$ARBRE"
poser() { install -D "$@"; }

poser -m 0755 "$BINAIRES/tordns-cles-onion" "$ARBRE/usr/local/bin/tordns-cles-onion"
poser -m 0755 "$BINAIRES/tordns-etat-local" "$ARBRE/usr/local/bin/tordns-etat-local"
poser -m 0755 "$BINAIRES/tordns-inscription" "$ARBRE/usr/local/bin/tordns-inscription"
poser -m 0755 "$RACINE/noeud/raspberry/premier-demarrage.sh" "$ARBRE/usr/local/lib/tordns/premier-demarrage.sh"
poser -m 0755 "$RACINE/noeud/raspberry/inscription.sh" "$ARBRE/usr/local/lib/tordns/inscription.sh"
poser -m 0644 "$RACINE/noeud/raspberry/pare-feu.nft" "$ARBRE/etc/tordns/pare-feu.nft"

for binaire in docker dockerd containerd containerd-shim-runc-v2 ctr runc docker-init docker-proxy; do
	poser -m 0755 "$TRAVAIL/docker-binaires/$binaire" "$ARBRE/usr/local/bin/$binaire"
done

for unite in containerd docker tordns-premier-demarrage tordns-inscription tordns-etat-local; do
	poser -m 0644 "$RACINE/noeud/raspberry/$unite.service" "$ARBRE/etc/systemd/system/$unite.service"
done
mkdir -p "$ARBRE/etc/systemd/system/multi-user.target.wants"
for unite in containerd docker tordns-premier-demarrage tordns-etat-local; do
	ln -s "/etc/systemd/system/$unite.service" \
		"$ARBRE/etc/systemd/system/multi-user.target.wants/$unite.service"
done
# L'assistant de premier démarrage de Raspberry Pi OS réclame un clavier et un
# mot de passe. Le désactiver ne suffit pas : un preset le réactive au premier
# démarrage, donc on le masque (/dev/null), ce qui tient dans tous les cas.
ln -s /dev/null "$ARBRE/etc/systemd/system/userconfig.service"

printf 'tordns\n' >"$ARBRE/etc/hostname"
cat >"$ARBRE/etc/hosts" <<'EOF'
127.0.0.1	localhost
::1		localhost ip6-localhost ip6-loopback
ff02::1		ip6-allnodes
ff02::2		ip6-allrouters
127.0.1.1	tordns
EOF
chmod 0644 "$ARBRE/etc/hostname" "$ARBRE/etc/hosts"

# Code du nœud, tel qu'il sera installé par l'installeur commun.
mkdir -p "$ARBRE/opt/tordns"
# Seuls les fichiers SUIVIS par git : depuis la mission 26, outils/arti-rust est un crate, et un
# `cargo build` préalable y laisse un target/ de plusieurs Gio qui remplissait la partition racine
# (le premier démarrage ne pouvait plus écrire /etc/machine-id ni les clés).
for dossier in noeud serveur outils; do
	[ -d "$RACINE/$dossier" ] || echec "$dossier absente du dépôt"
done
if git -C "$RACINE" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
	git -C "$RACINE" ls-files -z -- noeud serveur outils |
		tar -C "$RACINE" --null -T - -cf - | tar -C "$ARBRE/opt/tordns" -xpf - ||
		echec "copie du code du nœud"
else
	for dossier in noeud serveur outils; do
		cp -a "$RACINE/$dossier" "$ARBRE/opt/tordns/"
	done
	find "$ARBRE/opt/tordns" -type d -name target -prune -exec rm -rf {} +
fi
cp -a "$RACINE/README.md" "$ARBRE/opt/tordns/"
# Ce qui n'a rien à faire sur une carte : journaux de construction, caches.
find "$ARBRE/opt/tordns" \( -name '*.log' -o -name '__pycache__' \) -print0 | xargs -0 -r rm -rf
[ ! -e "$ARBRE/var/lib/tordns" ] || echec "l'arbre ne doit contenir aucune donnée du nœud"
ok "arbre posé : $(find "$ARBRE" -type f | wc -l) fichiers, $(find "$ARBRE" -type l | wc -l) liens"

# ---------------------------------------------------------------------------
section "5. Application dans les partitions"
# debugfs ne sait pas créer d'arborescence : on décrit chaque création.
COMMANDES=$TMP/debugfs.cmd
{
	printf 'cd /\n'
	# Les dossiers existants provoquent « File exists » : debugfs continue.
	find "$ARBRE" -mindepth 1 -type d | LC_ALL=C sort | while read -r dossier; do
		printf 'mkdir %s\n' "${dossier#"$ARBRE"}"
	done
	# debugfs refuse d'écraser un fichier existant : on supprime d'abord ceux
	# que l'image Raspberry Pi OS fournit déjà.
	for remplace in /etc/hostname /etc/hosts; do
		printf 'rm %s\n' "$remplace"
	done
	find "$ARBRE" -mindepth 1 -type f | LC_ALL=C sort | while read -r fichier; do
		printf 'write /t/image/arbre%s %s\n' "${fichier#"$ARBRE"}" "${fichier#"$ARBRE"}"
	done
	# Modes : les exécutables restent exécutables, tout le reste en 0644/0755.
	find "$ARBRE" -mindepth 1 -type f | LC_ALL=C sort | while read -r fichier; do
		if [ -x "$fichier" ]; then mode=0100755; else mode=0100644; fi
		printf 'sif %s mode %s\n' "${fichier#"$ARBRE"}" "$mode"
	done
	find "$ARBRE" -mindepth 1 -type d | LC_ALL=C sort | while read -r dossier; do
		case ${dossier#"$ARBRE"} in
		/var/lib/tordns*) mode=040700 ;;
		*) mode=040755 ;;
		esac
		printf 'sif %s mode %s\n' "${dossier#"$ARBRE"}" "$mode"
	done
	find "$ARBRE" -mindepth 1 -type l | LC_ALL=C sort | while read -r lien; do
		printf 'symlink %s %s\n' "${lien#"$ARBRE"}" "$(readlink "$lien")"
	done
	# L'assistant de premier démarrage de Raspberry Pi OS attend un clavier :
	# il bloquerait indéfiniment une carte sans écran, et créerait un compte
	# avec mot de passe, ce que cette image ne veut pas.
	printf 'rm /etc/systemd/system/multi-user.target.wants/userconfig.service\n'
} >"$COMMANDES"
[ "$(grep -c '^write ' "$COMMANDES")" -ge 10 ] || echec "commandes debugfs incomplètes"

# L'image d'origine est presque pleine : les binaires Docker ne tiennent pas
# dans les ~100 Mio libres. On agrandit la partition racine à 3 Gio ; la carte
# SD d'un bénévole est plus grande, et le premier démarrage l'étend encore.
conteneur "truncate -s 3G /t/image/racine.ext4; e2fsck -fp /t/image/racine.ext4 >/t/resize.log 2>&1 || true; resize2fs /t/image/racine.ext4 >>/t/resize.log 2>&1" ||
	{ cat "$TMP/resize.log" >&2; echec "agrandissement de la partition racine"; }
ok "partition racine agrandie à 3 Gio"

conteneur "debugfs -w -f /t/debugfs.cmd /t/image/racine.ext4 >/t/debugfs.log 2>&1" ||
	{ cat "$TMP/debugfs.log" >&2; echec "écriture dans la partition racine"; }
# debugfs signale « File exists » pour les dossiers déjà présents dans
# l'image (/etc, /usr/local…) : c'est attendu. On vérifie le résultat.
# stat_image capture la sortie : un tube vers grep -q tuerait debugfs.
stat_image() {
	conteneur "debugfs -R 'stat $1' /t/image/racine.ext4 2>/dev/null" | tr -d '\r'
}
for attendu in \
	/usr/local/bin/tordns-cles-onion \
	/usr/local/bin/tordns-etat-local \
	/usr/local/lib/tordns/premier-demarrage.sh \
	/etc/systemd/system/tordns-premier-demarrage.service \
	/etc/tordns/pare-feu.nft \
	/opt/tordns/noeud/installer.sh \
	/etc/hostname; do
	stat_image "$attendu" | grep -q 'Type: regular' ||
		echec "$attendu absent de la partition racine"
done
for lien in /etc/systemd/system/multi-user.target.wants/tordns-premier-demarrage.service \
	/etc/systemd/system/multi-user.target.wants/docker.service; do
	stat_image "$lien" | grep -q 'Type: symlink' ||
		echec "$lien absent de la partition racine"
done
if stat_image "/etc/systemd/system/multi-user.target.wants/userconfig.service" | grep -q 'Type:'; then
	echec "userconfig.service toujours activé dans l'image"
fi
stat_image "/etc/systemd/system/userconfig.service" | grep -q '/dev/null' ||
	echec "userconfig.service n'est pas masqué"
ok "partition racine modifiée"

# Exemple de demande d'inscription, sur la partition que le bénévole monte.
cp "$RACINE/noeud/raspberry/tordns.txt.exemple" "$TMP/exemple.txt"
conteneur "mcopy -o -i /t/image/boot.fat /t/exemple.txt ::tordns.txt.exemple" >/dev/null ||
	echec "écriture dans la partition de démarrage"
if conteneur "mdir -i /t/image/boot.fat :: | grep -q '^ssh'" >/dev/null 2>&1; then
	echec "un fichier ssh est présent : SSH serait activé"
fi
ok "partition de démarrage préparée, SSH désactivé"

# ---------------------------------------------------------------------------
section "6. Assemblage, compression, empreinte"
SORTIE=$DIST/tordns-noeud-rpi-$VERSION-arm64.img
rm -f "$SORTIE" "$SORTIE.xz" "$SORTIE.xz.sha256"
python3 "$RACINE/scripts/ci/rpi-partitions.py" assembler \
	"$TRAVAIL/base.img" "$TRAVAIL/boot.fat" "$TRAVAIL/racine.ext4" "$SORTIE"
python3 "$RACINE/scripts/ci/rpi-partitions.py" arrondir "$SORTIE"
xz -T0 -9 -c "$SORTIE" >"$SORTIE.xz"
(cd "$DIST" && sha256sum "$(basename "$SORTIE").xz" >"$(basename "$SORTIE").xz.sha256")
rm -f "$SORTIE"
ok "$(basename "$SORTIE").xz : $(stat -c '%s' "$SORTIE.xz") octets"
cat "$SORTIE.xz.sha256"
