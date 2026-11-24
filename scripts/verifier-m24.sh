#!/usr/bin/env bash
# TorDNS — preuve de la mission 24 (image nœud pour Raspberry Pi).
#
# Ce script construit l'image, l'inspecte hors ligne, puis la démarre deux fois
# dans QEMU `raspi3b` avec le noyau de l'image, dans un conteneur non privilégié
# (aucun montage, aucun périphérique, aucun init hôte). Attendu : le service de
# premier démarrage va au bout, crée des clés différentes sur deux copies
# neuves, et Tor (sur l'hôte) accepte ces clés.
#
# NON PROUVÉ : un vrai Raspberry Pi, une vraie carte SD, le matériel réel.
set -euo pipefail

RACINE=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
DIST=${DIST:-"$RACINE/dist/rpi"}
VERSION=${VERSION:-$("$RACINE/scripts/ci/version.sh")}
IMAGE="$DIST/tordns-noeud-rpi-$VERSION-arm64.img.xz"
OUTILS=tordns-rpi-outils
TMP=$(mktemp -d "${TMPDIR:-/tmp}/tordns-m24.XXXXXX")
trap 'rm -rf "$TMP"' EXIT

section() { printf '\n== %s ==\n' "$*"; }
ok() { printf 'OK : %s\n' "$*"; }
info() { printf '%s\n' "$*"; }
echec() { printf 'ÉCHEC : %s\n' "$*" >&2; exit 1; }
attention() { printf 'ATTENTION : %s\n' "$*" >&2; }

conteneur() {
	docker run --rm --user "$(id -u):$(id -g)" -v "$TMP":/t -w /t "$OUTILS" sh -c "$1"
}

docker info >/dev/null 2>&1 || echec "docker indisponible"
if [ "${TORDNS_SAUTER_CONSTRUCTION:-0}" != 1 ]; then
	section "1. Construction de l'image"
	"$RACINE/scripts/ci/image-rpi.sh" || echec "construction de l'image"
	ok "image construite"
else
	section "1. Construction de l'image (sautée)"
	info "TORDNS_SAUTER_CONSTRUCTION=1 : image déjà présente"
fi
[ -s "$IMAGE" ] || echec "image absente : $IMAGE"
[ -s "$IMAGE.sha256" ] || echec "empreinte absente : $IMAGE.sha256"
(cd "$DIST" && sha256sum -c --status "$(basename "$IMAGE").sha256") ||
	echec "empreinte de l'image incorrecte"
ok "image présente, $(stat -c '%s' "$IMAGE") octets, empreinte vérifiée"
if [ "$(stat -c '%s' "$IMAGE")" -gt 2147483648 ]; then
	echec "image compressée de plus de 2 Go"
fi
ok "image compressée sous 2 Go"

# ---------------------------------------------------------------------------
section "2. Inspection hors ligne : ni clé, ni mot de passe, ni SSH"
xz -dc "$IMAGE" >"$TMP/image.img"
stat_image() { conteneur "debugfs -R \"stat $1\" /t/racine.ext4 2>/dev/null" | tr -d '\r'; }
python3 "$RACINE/scripts/ci/rpi-partitions.py" extraire \
	"$TMP/image.img" "$TMP/boot.fat" "$TMP/racine.ext4"

# Aucune clé .onion : ni dossier de service caché, ni fichier hs_ed25519.
if conteneur "debugfs -R 'ls -l /var/lib/tordns/tor' /t/racine.ext4 2>/dev/null" |
	grep -qi 'hs_ed25519\|hostname'; then
	echec "des clés .onion sont présentes dans l'image"
fi
if conteneur "debugfs -R 'ls -l /var/lib/tordns' /t/racine.ext4 2>/dev/null" |
	grep -qi 'premier-demarrage.ok'; then
	echec "l'image contient déjà un marqueur de premier démarrage"
fi
ok "aucune clé .onion, aucun marqueur : l'identité naîtra sur la carte"

conteneur "debugfs -R 'dump /etc/shadow /t/shadow' /t/racine.ext4 >/dev/null 2>&1"
ouverts=$(awk -F: '$2 != "*" && $2 !~ /^!/ { print $1 }' "$TMP/shadow")
[ -z "$ouverts" ] || echec "comptes sans mot de passe verrouillé : $ouverts"
ok "aucun compte avec mot de passe utilisable ($(wc -l <"$TMP/shadow") lignes vérifiées)"

if stat_image "/etc/systemd/system/multi-user.target.wants/ssh.service" | grep -q 'Type:'; then
	echec "ssh.service activé dans l'image"
fi
if conteneur "mdir -i /t/boot.fat :: 2>/dev/null" | grep -qi '^ssh'; then
	echec "fichier ssh présent sur la partition de démarrage"
fi
if stat_image "/etc/systemd/system/multi-user.target.wants/userconfig.service" | grep -q 'Type:'; then
	echec "userconfig.service toujours activé"
fi
if ! stat_image "/etc/systemd/system/userconfig.service" | grep -q '/dev/null'; then
	echec "userconfig.service n'est pas masqué (un preset le relancerait)"
fi
ok "SSH désactivé par défaut, assistant de premier démarrage retiré"

for attendu in \
	/usr/local/bin/dockerd /usr/local/bin/containerd \
	/usr/local/bin/tordns-cles-onion /usr/local/bin/tordns-etat-local \
	/usr/local/lib/tordns/premier-demarrage.sh \
	/etc/systemd/system/tordns-premier-demarrage.service \
	/etc/systemd/system/tordns-etat-local.service \
	/etc/tordns/pare-feu.nft /opt/tordns/noeud/installer.sh \
	/opt/tordns/serveur /opt/tordns/outils; do
	stat_image "$attendu" | grep -q 'Type:' || echec "$attendu absent de l'image"
done
ok "Docker, outils du premier démarrage, page d'état et code du nœud présents"

conteneur "debugfs -R 'dump /etc/hostname /t/hostname' /t/racine.ext4 >/dev/null 2>&1"
grep -qx 'tordns' "$TMP/hostname" || echec "nom d'hôte inattendu : $(cat "$TMP/hostname")"
ok "nom d'hôte tordns (donc tordns.local par avahi)"

conteneur "debugfs -R 'dump /etc/tordns/pare-feu.nft /t/pare-feu.nft' /t/racine.ext4 >/dev/null 2>&1"
grep -q 'policy drop' "$TMP/pare-feu.nft" || echec "pare-feu sans politique par défaut en rejet"
grep -q 'tcp dport 80 accept' "$TMP/pare-feu.nft" || echec "page d'état non autorisée"
ok "pare-feu : tout fermé sauf la page d'état sur le LAN"
info "syntaxe nftables non vérifiable ici (nft -c exige root) : elle l'est au"
info "démarrage, où le service n'annonce « pare-feu appliqué » que si nft rend 0."

# ---------------------------------------------------------------------------
section "3. Deux démarrages dans QEMU raspi3b (noyau de l'image)"
# Le noyau de l'image démarre bien sur raspi3b, mais QEMU n'émule pas le
# chien de garde du Pi : systemd redémarre la machine toutes les 13 s tant que
# WatchdogDevice pointe dessus. On ajoute donc un fichier de configuration
# **dans la copie d'essai**, jamais dans l'image livrée.
printf '[Manager]\nWatchdogDevice=/dev/watchdog666\n' >"$TMP/watchdog.conf"

conteneur "mcopy -o -i /t/boot.fat ::kernel8.img ::bcm2710-rpi-3-b.dtb /t/" >/dev/null ||
	echec "noyau ou arbre de périphériques absent de la partition de démarrage"

demarrer() {
	local numero=$1
	local image="$TMP/essai-$numero.img"
	local racine="$TMP/racine-$numero.ext4"
	local boot="$TMP/boot-$numero.fat"
	cp "$TMP/image.img" "$image"
	python3 "$RACINE/scripts/ci/rpi-partitions.py" extraire "$image" "$boot" "$racine"
	conteneur "debugfs -w -R 'mkdir /etc/systemd/system.conf.d' /t/$(basename "$racine") >/dev/null 2>&1;
		debugfs -w -R 'write /t/watchdog.conf /etc/systemd/system.conf.d/00-qemu-watchdog.conf' /t/$(basename "$racine") >/dev/null 2>&1;
		debugfs -w -R 'sif /etc/systemd/system.conf.d/00-qemu-watchdog.conf mode 0100644' /t/$(basename "$racine") >/dev/null 2>&1"
	rm -f "$image"
	python3 "$RACINE/scripts/ci/rpi-partitions.py" assembler \
		"$TMP/image.img" "$boot" "$racine" "$image"
	python3 "$RACINE/scripts/ci/rpi-partitions.py" arrondir "$image"

	info "démarrage $numero (jusqu'à ${TORDNS_ATTENTE_DEMARRAGE:-600}s)"
	timeout "${TORDNS_ATTENTE_DEMARRAGE:-600}" docker run --rm --user "$(id -u):$(id -g)" \
		-v "$TMP":/t -w /t "$OUTILS" qemu-system-aarch64 \
		-M raspi3b -cpu cortex-a53 -m 1024 -smp 4 \
		-kernel /t/kernel8.img -dtb /t/bcm2710-rpi-3-b.dtb \
		-append "rw earlyprintk loglevel=7 console=ttyAMA1,115200 dwc_otg.lpm_enable=0 root=/dev/mmcblk0p2 rootdelay=1" \
		-drive "file=/t/$(basename "$image"),format=raw,if=sd" \
		-display none -monitor none -serial "file:/t/serie-$numero.log" || true

	grep -q 'premier-demarrage.sh.*terminé' "$TMP/serie-$numero.log" ||
		{ tail -n 20 "$TMP/serie-$numero.log" >&2; echec "démarrage $numero : premier démarrage non terminé"; }
	grep -q 'clés écrites dans /var/lib/tordns/tor/hs' "$TMP/serie-$numero.log" ||
		{ tail -n 20 "$TMP/serie-$numero.log" >&2; echec "démarrage $numero : clés non créées"; }
	grep -q 'pare-feu appliqué' "$TMP/serie-$numero.log" ||
		{ tail -n 20 "$TMP/serie-$numero.log" >&2; echec "démarrage $numero : pare-feu non appliqué (nft a échoué)"; }
	ok "démarrage $numero : premier démarrage terminé, clés créées, pare-feu chargé"

	# Les clés vivent sur la carte : on les relit dans la partition après arrêt.
	python3 "$RACINE/scripts/ci/rpi-partitions.py" extraire "$image" "$boot" "$racine"
	conteneur "e2fsck -fy /t/$(basename "$racine") >/dev/null 2>&1 || true;
		debugfs -R 'dump /var/lib/tordns/tor/hs/hs_ed25519_secret_key /t/cle-$numero' /t/$(basename "$racine") >/dev/null 2>&1"
	[ -s "$TMP/cle-$numero" ] || echec "démarrage $numero : clé absente de la carte"
	[ "$(stat -c '%s' "$TMP/cle-$numero")" -eq 96 ] ||
		echec "démarrage $numero : clé de $(stat -c '%s' "$TMP/cle-$numero") octets, 96 attendus"
}

demarrer 1
demarrer 2

somme1=$(sha256sum <"$TMP/cle-1" | cut -d' ' -f1)
somme2=$(sha256sum <"$TMP/cle-2" | cut -d' ' -f1)
[ "$somme1" != "$somme2" ] || echec "les deux copies ont la même clé"
ok "deux cartes neuves, deux clés différentes (${somme1:0:12}… ≠ ${somme2:0:12}…)"

# ---------------------------------------------------------------------------
section "4. Tor accepte les clés créées par la carte"
if ! command -v tor >/dev/null 2>&1; then
	attention "tor absent sur cette machine : validité des clés NON PROUVÉE"
else
	mkdir -p "$TMP/hs" "$TMP/tordonnees"
	chmod 700 "$TMP/hs" "$TMP/tordonnees"
	cp "$TMP/cle-1" "$TMP/hs/hs_ed25519_secret_key"
	chmod 600 "$TMP/hs/hs_ed25519_secret_key"
	cat >"$TMP/torrc" <<EOF
SocksPort 0
DataDirectory $TMP/tordonnees
HiddenServiceDir $TMP/hs
HiddenServicePort 80 127.0.0.1:8080
EOF
	timeout 40 tor -f "$TMP/torrc" >"$TMP/tor.log" 2>&1 || true
	if grep -qi 'does not match\|Error loading rendezvous\|Reading config failed' "$TMP/tor.log"; then
		grep -i 'does not match\|Error loading\|Reading config failed' "$TMP/tor.log" >&2
		echec "Tor refuse les clés écrites sur la carte"
	fi
	[ -s "$TMP/hs/hostname" ] || echec "Tor n'a pas écrit d'adresse d'instance"
	adresse=$(tr -d '\r\n ' <"$TMP/hs/hostname")
	case $adresse in
	*.onion) ;;
	*) echec "adresse inattendue : $adresse" ;;
	esac
	[ "${#adresse}" -eq 62 ] || echec "adresse de ${#adresse} caractères, 62 attendus"
	ok "Tor 0.4.9 lit les clés et publie une adresse d'instance (${adresse:0:12}…)"
fi

# ---------------------------------------------------------------------------
section "5. Ce qui n'est pas prouvé"
info "NON PROUVÉ : un vrai Raspberry Pi (démarrage, chien de garde, SD, SSD,"
info "consommation) ; l'extension de la partition sur une carte réelle ;"
info "l'installation du nœud par images GHCR (noeud/images.txt absent du dépôt :"
info "le premier démarrage l'a signalé et a continué) ; l'inscription réelle au"
info "registre ; la page tordns.local depuis un autre appareil du LAN."

printf '\ncode=0\n'
