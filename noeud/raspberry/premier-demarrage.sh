#!/bin/sh
# TorDNS — premier démarrage d'une carte nœud (Mission 24).
#
# Exécuté une seule fois par tordns-premier-demarrage.service, en root :
#   1. étend la partition racine à la carte (l'image est plus petite qu'une SD) ;
#   2. crée les clés du service caché sur la carte — jamais dans l'image ;
#   3. active le pare-feu : rien n'entre sauf la page d'état sur le LAN ;
#   4. installe le nœud (images GHCR épinglées) si noeud/images.txt est présent ;
#   5. prépare l'inscription au registre si /boot/firmware/tordns.txt la demande.
#
# Idempotent : un marqueur /var/lib/tordns/premier-demarrage.ok arrête tout.
set -eu

DONNEES=/var/lib/tordns
CODE=/opt/tordns
BOOT=/boot/firmware
MARQUEUR=$DONNEES/premier-demarrage.ok
SERVICE=tordns-premier-demarrage

journal() { printf '%s : %s\n' "$SERVICE" "$*"; }
avertir() { printf '%s : AVERTISSEMENT : %s\n' "$SERVICE" "$*" >&2; }

if [ -f "$MARQUEUR" ]; then
	journal "déjà effectué, rien à faire"
	exit 0
fi

# 0. Utilisateur système du nœud (l'installeur le retrouve par son nom).
if ! id -u tordns >/dev/null 2>&1; then
	useradd --system --no-create-home --home-dir "$DONNEES" \
		--shell /usr/sbin/nologin tordns ||
		avertir "création de l'utilisateur tordns impossible"
fi

# 1. Partition racine.
journal "extension de la partition racine"
if command -v raspi-config >/dev/null 2>&1; then
	raspi-config nonint do_expand_rootfs || avertir "raspi-config n'a pas étendu la partition"
else
	avertir "raspi-config absent : la partition racine reste à sa taille d'image"
fi

# 2. Clés du service caché, créées sur la carte.
journal "clés du service caché"
install -d -m 0700 -o tordns -g tordns "$DONNEES/tor"
if [ -e "$DONNEES/tor/hs/hs_ed25519_secret_key" ]; then
	journal "identité déjà présente, conservée"
else
	runuser -u tordns -- /usr/local/bin/tordns-cles-onion -dossier "$DONNEES/tor/hs" ||
		avertir "génération des clés impossible"
fi

# 3. Pare-feu : tout est fermé sauf la page d'état sur le LAN.
# Le chargement est la seule validation réelle des règles : il n'est annoncé
# comme réussi que si nft rend 0 (la vérification hors ligne exige root).
if command -v nft >/dev/null 2>&1; then
	if nft -f /etc/tordns/pare-feu.nft; then
		journal "pare-feu appliqué"
	else
		journal "pare-feu : ÉCHEC du chargement nftables"
		avertir "chargement nftables impossible"
	fi
else
	journal "pare-feu : ÉCHEC (nft absent)"
	avertir "nft absent : pare-feu non chargé"
fi

# 4. Nœud : installation par l'installeur commun, images GHCR épinglées.
if [ -f "$CODE/noeud/images.txt" ]; then
	journal "attente de Docker"
	docker_pret=0
	essai=0
	while [ "$essai" -lt 30 ]; do
		if docker info >/dev/null 2>&1; then
			docker_pret=1
			break
		fi
		essai=$((essai + 1))
		sleep 10
	done
	if [ "$docker_pret" -eq 1 ]; then
		journal "installation du nœud (images GHCR épinglées)"
		if ! (cd "$CODE" && ./noeud/installer.sh --images ghcr --sans-docker --sans-attente); then
			avertir "installation du nœud en échec : voir journalctl -u $SERVICE"
		fi
	else
		avertir "Docker ne répond pas après 300s : nœud non installé"
	fi
else
	avertir "noeud/images.txt absent : nœud non installé (images non épinglées)"
fi

# 5. Demande d'inscription lue sur la partition de démarrage.
if [ -f "$BOOT/tordns.txt" ]; then
	journal "tordns.txt présent : inscription demandée"
	install -d -m 0755 /etc/tordns
	chmod 0644 "$BOOT/tordns.txt" 2>/dev/null || true
	# Le fichier est relu par tordns-inscription.service ; on n'en garde ici
	# qu'une copie pour l'audit local, sans contact publié.
	cp "$BOOT/tordns.txt" /etc/tordns/tordns.txt
	systemctl enable tordns-inscription.service 2>/dev/null ||
		avertir "activation de tordns-inscription.service impossible"
else
	journal "aucun tordns.txt : pas d'inscription au registre"
fi

install -m 0600 /dev/null "$MARQUEUR"
journal "terminé"
