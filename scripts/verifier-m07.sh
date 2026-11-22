#!/usr/bin/env bash
# TorDNS — preuve de la Mission 7 (durcissement).
#
# Vérifie : Tor sans SOCKS, PoW/streams/vanguards, PROXY v2 de bout en bout,
# limite par circuit (deux circuits distincts), DNSSEC et SERVFAIL via le
# .onion, et absence de journal de requêtes. Aucun accès distant.
set -euo pipefail
RACINE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$RACINE/serveur"
CLIENT=tordns-tor-client
ONION=""

echec() {
	echo "ÉCHEC : $*" >&2
	exit 1
}

echo "== 1. Stack, service caché et client Tor de test =="
docker compose up -d --build
# Caddy lit son Caddyfile au démarrage : un simple changement de fichier monté
# n'est pas détecté par compose.
docker compose restart caddy >/dev/null
for _ in $(seq 1 60); do
	ONION="$(docker exec tordns-tor cat /var/lib/tor/hidden_service/hostname 2>/dev/null | tr -d '\r\n' || true)"
	[ -n "$ONION" ] && break
	sleep 2
done
[ -n "$ONION" ] || echec "service caché non publié"
echo "Service caché publié (adresse non affichée)."

docker compose --profile test up -d --build tor-client >/dev/null
pret=false
for _ in $(seq 1 30); do
	if docker exec "$CLIENT" curl -sS --max-time 10 --socks5-hostname 127.0.0.1:9050 \
		-o /dev/null "http://$ONION/healthz" 2>/dev/null; then
		pret=true
		break
	fi
	sleep 2
done
[ "$pret" = true ] || echec "le client Tor de test ne joint pas le .onion"
echo "Client Tor de test prêt (profil test, aucun port publié)."

echo
echo "== 2. Versions minimales (Tor >= 0.4.8, Caddy >= 2.7) =="
version_tor="$(docker exec tordns-tor tor --version | sed -n 's/^Tor version \([0-9.]*\)\..*/\1/p' | head -1)"
version_caddy="$(docker exec tordns-caddy caddy version | sed -n 's/^v\([0-9.]*\) .*/\1/p')"
echo "Tor $version_tor, Caddy $version_caddy"
printf '0.4.8\n%s\n' "$version_tor" | sort -V -C || echec "Tor < 0.4.8 : PoW indisponible"
printf '2.7\n%s\n' "$version_caddy" | sort -V -C || echec "Caddy < 2.7 : PROXY protocol indisponible"

echo
echo "== 3. Tor du nœud : SOCKS fermé et options de défense =="
docker exec tordns-tor sh -c 'grep -E "^(SocksPort|HiddenServiceExportCircuitID|HiddenServicePoWDefensesEnabled|HiddenServiceMaxStreams|HiddenServiceMaxStreamsCloseCircuit|VanguardsLiteEnabled)" /etc/tor/torrc'
docker exec tordns-tor tor --verify-config -f /etc/tor/torrc >/dev/null
echo "Configuration Tor valide."
if docker exec tordns-tor sh -c 'netstat -ltn 2>/dev/null | grep -q ":9050"'; then
	echec "le nœud écoute encore sur le port SOCKS 9050"
fi
if [ -n "$(docker port tordns-tor 2>/dev/null)" ]; then
	echec "le conteneur Tor publie un port sur l'hôte"
fi
echo "Aucune écoute SOCKS et aucun port publié par le nœud."

echo
echo "== 4. DoH réel par le .onion : DNSSEC et SERVFAIL =="
requete="$(mktemp)"
reponse="$(mktemp)"
trap 'rm -f "$requete" "$reponse"' EXIT
# ID 0x1234, RD, 1 question (example.com. A IN), EDNS0 OPT avec bit DO.
printf '\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01\x07example\x03com\x00\x00\x01\x00\x01\x00\x00\x29\x04\xd0\x00\x00\x80\x00\x00\x00' >"$requete"
docker exec -i "$CLIENT" sh -c 'cat > /tmp/requete' <"$requete"
code="$(docker exec "$CLIENT" curl -sS --max-time 90 --socks5-hostname 127.0.0.1:9050 \
	-o /tmp/reponse -w '%{http_code}' \
	-H 'accept: application/dns-message' \
	-H 'content-type: application/dns-message' \
	--data-binary @/tmp/requete \
	"http://$ONION/dns-query")"
docker exec "$CLIENT" cat /tmp/reponse >"$reponse"
octets="$(wc -c <"$reponse")"
identifiant="$(head -c 2 "$reponse" | od -An -tx1 | tr -d ' \n')"
drapeaux="$(od -An -j2 -N2 -tx1 "$reponse" | tr -d ' \n')"
echo "example.com A : HTTP $code, $octets octets, ID $identifiant, drapeaux 0x$drapeaux"
[ "$code" = 200 ] && [ "$octets" -ge 12 ] && [ "$identifiant" = 1234 ] || echec "réponse DoH invalide"
[ "$drapeaux" != "" ] || echec "drapeaux DNS illisibles"
if ((0x$drapeaux & 0x000F)); then
	echec "rcode non nul pour example.com"
fi
if ((0x$drapeaux & 0x0020)); then
	echo "AD présent : DNSSEC validé de bout en bout."
else
	echec "bit AD absent"
fi

# dnssec-failed.org : signature cassée, Unbound doit répondre SERVFAIL.
printf '\x12\x35\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01\x0ddnssec-failed\x03org\x00\x00\x01\x00\x01\x00\x00\x29\x04\xd0\x00\x00\x80\x00\x00\x00' >"$requete"
docker exec -i "$CLIENT" sh -c 'cat > /tmp/requete' <"$requete"
code="$(docker exec "$CLIENT" curl -sS --max-time 90 --socks5-hostname 127.0.0.1:9050 \
	-o /tmp/reponse -w '%{http_code}' \
	-H 'accept: application/dns-message' \
	-H 'content-type: application/dns-message' \
	--data-binary @/tmp/requete \
	"http://$ONION/dns-query")"
docker exec "$CLIENT" cat /tmp/reponse >"$reponse"
drapeaux="$(od -An -j2 -N2 -tx1 "$reponse" | tr -d ' \n')"
rcode=$((0x$drapeaux & 0x000F))
echo "dnssec-failed.org A : HTTP $code, rcode=$rcode (attendu 2/SERVFAIL)"
[ "$code" = 200 ] && [ "$rcode" -eq 2 ] || echec "signature cassée non refusée"

echo
echo "== 5. Limite par circuit à travers Caddy (PROXY) =="
docker exec -i "$CLIENT" sh -c 'cat > /tmp/requete-proxy.sh' < scripts/requete-proxy.sh
circuit_a="fc00:dead:beef:4dad::a:a"
circuit_b="fc00:dead:beef:4dad::b:b"
statuts="$(docker exec "$CLIENT" sh -c "seq 1 80 | xargs -P 10 -I{} sh /tmp/requete-proxy.sh $circuit_a")"
refus="$(printf '%s\n' "$statuts" | grep -c '429' || true)"
echo "Circuit A : 80 requêtes, $refus refusées (HTTP 429)."
[ "$refus" -gt 0 ] || echec "aucune requête refusée pour le circuit A"
sleep 0.3
statut_b="$(docker exec "$CLIENT" sh /tmp/requete-proxy.sh "$circuit_b")"
echo "Circuit B : $statut_b"
case "$statut_b" in
"HTTP/1.1 200 OK"*) ;;
*) echec "le circuit B est pénalisé par le circuit A" ;;
esac

echo
echo "== 6. Aucun nom de domaine dans un journal =="
nom="m07-$(date +%s)-$$.invalid"
docker exec "$CLIENT" curl -sS --max-time 90 --socks5-hostname 127.0.0.1:9050 \
	-o /dev/null "http://$ONION/dns-query?name=$nom&type=A"
for conteneur in tordns-unbound tordns-passerelle tordns-caddy tordns-tor tordns-tor-client; do
	driver="$(docker inspect "$conteneur" --format '{{.HostConfig.LogConfig.Type}}')"
	chemin="$(docker inspect "$conteneur" --format '{{.LogPath}}')"
	if [ "$driver" != "none" ]; then
		if docker logs "$conteneur" 2>&1 | grep -qF "$nom"; then
			echec "$conteneur a journalisé le nom demandé"
		fi
		echo "$conteneur : driver=$driver, aucune occurrence du nom."
	else
		echo "$conteneur : driver=none (aucun journal conservé, LogPath='$chemin')."
	fi
done

echo
echo "Mission 7 : toutes les preuves sont passées."
