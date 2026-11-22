#!/usr/bin/env bash
# TorDNS — gestion des clés du service caché Tor v3 (Mission 2).
#
# Les clés sont générées par Tor dans le volume docker `tor-data` (hors dépôt).
# Ce script permet de récupérer l'adresse .onion et d'exporter une sauvegarde
# chiffrable dans serveur/cles-onion/ (ignoré par git).
#
# Usage :
#   ./scripts/gestion-cles.sh adresse      # affiche l'adresse .onion
#   ./scripts/gestion-cles.sh sauvegarder  # copie les clés dans cles-onion/
#   ./scripts/gestion-cles.sh verifier     # contrôle qu'aucune clé n'est suivie
set -euo pipefail
cd "$(dirname "$0")/.."

CONTENEUR="tordns-tor"
DOSSIER_VOLUME="/var/lib/tor/hidden_service"
SAUVEGARDE="cles-onion"

attendre_service() {
	local i
	for i in $(seq 1 60); do
		if docker exec "$CONTENEUR" test -s "$DOSSIER_VOLUME/hostname" 2>/dev/null; then
			return 0
		fi
		sleep 2
	done
	echo "Le service caché n'est pas prêt (Tor démarré ? bootstrap réseau ?)." >&2
	return 1
}

cmd_adresse() {
	attendre_service
	docker exec "$CONTENEUR" cat "$DOSSIER_VOLUME/hostname"
}

cmd_sauvegarder() {
	if ! git check-ignore -q "$SAUVEGARDE/hostname"; then
		echo "REFUS : $SAUVEGARDE n'est pas ignoré par git. Arrêt." >&2
		exit 1
	fi
	attendre_service
	umask 077
	rm -rf "$SAUVEGARDE"
	mkdir -p "$SAUVEGARDE"
	docker cp "$CONTENEUR:$DOSSIER_VOLUME/." "$SAUVEGARDE/"
	chmod 700 "$SAUVEGARDE"
	find "$SAUVEGARDE" -type f -exec chmod 600 {} +
	echo "Clés sauvegardées dans $SAUVEGARDE/ (hors dépôt, 0600)."
	echo "Adresse : $(cat "$SAUVEGARDE/hostname")"
	echo "Cette sauvegarde est le SEUL moyen de conserver l'adresse .onion :"
	echo "conservez-la chiffrée hors de la machine si vous la recréez ailleurs."
}

cmd_verifier() {
	local suivis
	suivis="$(git ls-files | grep -E '(cles-onion|hidden_service|hs_ed25519|\.onion$)' || true)"
	if [ -n "$suivis" ]; then
		echo "ÉCHEC : des clés ou adresses .onion sont suivies par git :" >&2
		echo "$suivis" >&2
		exit 1
	fi
	if [ -e "$SAUVEGARDE/hostname" ]; then
		echo "OK : sauvegarde locale présente et ignorée par git."
	else
		echo "OK : aucune clé suivie par git (aucune sauvegarde locale)."
	fi
}

case "${1:-}" in
adresse) cmd_adresse ;;
sauvegarder) cmd_sauvegarder ;;
verifier) cmd_verifier ;;
*)
	echo "Usage : $0 {adresse|sauvegarder|verifier}" >&2
	exit 2
	;;
esac
