#!/bin/sh
# Envoie une requête DoH JSON à Caddy en précédant la connexion d'un en-tête
# PROXY v1, comme Tor le fait derrière un service caché. Utilisé par
# scripts/verifier-m07.sh pour distinguer deux circuits sans dépendre de Tor.
#
# $1 = adresse source IPv6 (ses 32 derniers bits forment l'identifiant de
#      circuit) ; $2 = nom demandé (facultatif, example.com par défaut).
set -eu
source_circuit="$1"
nom="${2:-example.com}"

{
	printf 'PROXY TCP6 %s ::1 12345 8080\r\n' "$source_circuit"
	printf 'GET /dns-query?name=%s&type=A HTTP/1.1\r\n' "$nom"
	printf 'Host: test\r\nAccept: application/dns-json\r\nConnection: close\r\n\r\n'
	# Garder la connexion ouverte le temps que Caddy transmette et réponde.
	sleep 0.05
} | nc caddy 8080 | head -1
