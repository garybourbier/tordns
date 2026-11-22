#!/usr/bin/env bash
# TorDNS — preuves locales des Missions 1 et 2.
# À lancer après : docker compose up -d --build (depuis serveur/).
#
# Aucun port de Unbound ni de Caddy n'est publié : ils ne sont joignables que
# par le réseau docker privé. La preuve DoH passe donc par le service caché,
# comme un vrai client Tor.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ -f .env ]; then
	set -a
	# shellcheck disable=SC1091
	. ./.env
	set +a
fi
SOCKS_PORT="${TOR_SOCKS_PORT:-9050}"

echo "== 1. Résolveur récursif, DNSSEC validé (dig dans le conteneur Unbound) =="
# Aucun port publié : on exécute dig au plus près du résolveur, sur 127.0.0.1.
docker exec tordns-unbound dig @127.0.0.1 -p 5335 example.com A +dnssec +nocmd +nostats

echo
echo "== 2. Adresse .onion du service caché v3 =="
onion=""
for _ in $(seq 1 60); do
	onion="$(docker exec tordns-tor cat /var/lib/tor/hidden_service/hostname 2>/dev/null | tr -d '\r\n' || true)"
	[ -n "$onion" ] && break
	sleep 2
done
if [ -z "$onion" ]; then
	echo "ÉCHEC : service caché non publié (voir docker logs tordns-tor)." >&2
	exit 1
fi
echo "$onion"

echo
echo "== 3. DoH filaire (RFC 8484, POST) à travers Tor =="
requete="$(mktemp)"
reponse="$(mktemp)"
# ID 0x1234, RD, 1 question (example.com. A IN), EDNS0 OPT avec bit DO.
printf '\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01\x07example\x03com\x00\x00\x01\x00\x01\x00\x00\x29\x04\xd0\x00\x00\x80\x00\x00\x00' >"$requete"
code="$(curl -sS --max-time 90 --socks5-hostname "127.0.0.1:$SOCKS_PORT" \
	-o "$reponse" -w '%{http_code}' \
	-H 'accept: application/dns-message' \
	-H 'content-type: application/dns-message' \
	--data-binary @"$requete" \
	"http://$onion/dns-query")"
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
echo "== 4. DoH lisible (JSON) à travers Tor =="
json="$(curl -sS --max-time 90 --socks5-hostname "127.0.0.1:$SOCKS_PORT" \
	-H 'accept: application/dns-json' \
	"http://$onion/dns-query?name=example.com&type=A")"
echo "$json"
case "$json" in
*'"Status":0'*) ;;
*)
	echo "ÉCHEC : statut DNS non nul." >&2
	exit 1
	;;
esac
case "$json" in
*'"AD":true'*) echo "DNSSEC : AD=true." ;;
*)
	echo "ÉCHEC : AD absent du JSON." >&2
	exit 1
	;;
esac

echo
echo "== 5. Cloisonnement réseau =="
docker ps --filter name=tordns --format '{{.Names}} {{.Ports}}'
# `docker port` ne liste que les publications réelles (pas les EXPOSE).
for c in tordns-unbound tordns-passerelle tordns-caddy; do
	if [ -n "$(docker port "$c" 2>/dev/null)" ]; then
		echo "ÉCHEC : $c est publié sur l'hôte ($(docker port "$c" | tr '\n' ' '))." >&2
		exit 1
	fi
done
if docker network inspect tordns_dns --format '{{.Internal}}' | grep -qx true; then
	echo "OK : réseau docker privé interne, aucun port DNS/DoH publié."
else
	echo "ÉCHEC : le réseau docker privé n'est pas interne." >&2
	exit 1
fi

echo
echo "== 6. Aucune clé ni adresse .onion dans le dépôt =="
./scripts/gestion-cles.sh verifier
