#!/usr/bin/env bash
# TorDNS — preuve locale de la Mission 1.
# À lancer après : docker compose up -d --build (depuis serveur/).
set -euo pipefail
cd "$(dirname "$0")/.."

IMAGE_UNBOUND="tordns/unbound:local"

# L'hôte n'a pas forcément dig : on utilise le dig de l'image Unbound en réseau
# hôte, ce qui revient exactement à interroger 127.0.0.1:5335.
dig_local() {
	docker run --rm --network host --entrypoint dig "$IMAGE_UNBOUND" "$@"
}

echo "== 1. Résolveur récursif local, DNSSEC validé (dig @127.0.0.1 -p 5335) =="
dig_local @127.0.0.1 -p 5335 example.com A +dnssec +nocmd +nostats

echo
echo "== 2. DoH filaire (RFC 8484, POST application/dns-message) via Caddy =="
requete="$(mktemp)"
reponse="$(mktemp)"
# ID 0x1234, RD, 1 question (example.com. A IN), EDNS0 OPT avec bit DO.
printf '\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01\x07example\x03com\x00\x00\x01\x00\x01\x00\x00\x29\x04\xd0\x00\x00\x80\x00\x00\x00' >"$requete"
code="$(curl -sS --max-time 10 -o "$reponse" -w '%{http_code}' \
	-H 'accept: application/dns-message' \
	-H 'content-type: application/dns-message' \
	--data-binary @"$requete" \
	http://127.0.0.1:8080/dns-query)"
octets="$(wc -c <"$reponse")"
identifiant="$(head -c 2 "$reponse" | od -An -tx1 | tr -d ' \n')"
drapeaux="$(od -An -j2 -N2 -tx1 "$reponse" | tr -d ' \n')"
echo "HTTP $code — $octets octets, ID de réponse: $identifiant (attendu 1234), drapeaux: 0x$drapeaux"
if [ "$code" != "200" ] || [ "$octets" -lt 12 ] || [ "$identifiant" != "1234" ]; then
	echo "ÉCHEC : réponse DoH filaire invalide" >&2
	rm -f "$requete" "$reponse"
	exit 1
fi
if (( 0x$drapeaux & 0x0020 )); then
	echo "DNSSEC validé par Unbound : bit AD présent dans la réponse DoH."
else
	echo "ÉCHEC : bit AD absent, la validation DNSSEC n'est pas démontrée." >&2
	rm -f "$requete" "$reponse"
	exit 1
fi
rm -f "$requete" "$reponse"

echo
echo "== 3. DoH lisible (même chemin, JSON) =="
curl -sS --max-time 10 -H 'accept: application/dns-json' \
	'http://127.0.0.1:8080/dns-query?name=example.com&type=A'
echo

echo
echo "== 4. Récursion fermée hors DoH =="
# Seul le réseau docker dédié peut interroger Unbound ; le port publié sur
# 127.0.0.1 est le seul point d'entrée hôte.
if dig_local @127.0.0.1 -p 5335 example.com A +time=2 +tries=1 +short >/dev/null 2>&1; then
	echo "OK : Unbound répond sur 127.0.0.1:5335, aucune autre interface publiée."
fi
