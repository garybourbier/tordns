#!/usr/bin/env bash
# TorDNS — preuves locales des Missions 1, 2 et 3.
# À lancer après : docker compose up -d --build (depuis serveur/).
#
# Aucun port de Unbound ni de Caddy n'est publié : ils ne sont joignables que
# par le réseau docker privé. La preuve DoH passe donc par le service caché,
# comme un vrai client Tor.
set -euo pipefail
cd "$(dirname "$0")/.."

# Le nœud n'ouvre plus de SOCKS (Mission 7) : les preuves passent par un
# client Tor séparé, sans port publié, qui sait joindre le .onion.
CLIENT=tordns-tor-client
docker compose --profile test up -d --build tor-client >/dev/null

tor_curl() {
	docker exec "$CLIENT" curl --socks5-hostname 127.0.0.1:9050 "$@"
}

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
docker exec -i "$CLIENT" sh -c 'cat > /tmp/requete' <"$requete"
code="$(docker exec "$CLIENT" curl -sS --max-time 90 --socks5-hostname 127.0.0.1:9050 \
	-o /tmp/reponse -w '%{http_code}' \
	-H 'accept: application/dns-message' \
	-H 'content-type: application/dns-message' \
	--data-binary @/tmp/requete \
	"http://$onion/dns-query")"
docker exec "$CLIENT" cat /tmp/reponse >"$reponse"
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
json="$(tor_curl -sS --max-time 90 \
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
for c in tordns-unbound tordns-passerelle tordns-caddy tordns-tor; do
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

echo
echo "== 7. Durcissement : ANY refusé, anti-amplification =="
# deny-any: Unbound répond NOTIMP (ou REFUSED) sans jamais résoudre l'ANY.
statut_any="$(docker exec tordns-unbound dig @127.0.0.1 -p 5335 example.com ANY +nocmd +nostats \
	| sed -n 's/.*status: \([A-Z]*\).*/\1/p' | head -1)"
echo "ANY example.com -> $statut_any (attendu NOTIMP ou REFUSED)"
case "$statut_any" in
NOTIMP | REFUSED) ;;
*)
	echo "ÉCHEC : les requêtes ANY ne sont pas refusées." >&2
	exit 1
	;;
esac
for option in edns-buffer-size max-udp-size; do
	valeur="$(docker exec tordns-unbound unbound-checkconf -o "$option")"
	echo "$option = $valeur"
	if [ "$valeur" != "1232" ]; then
		echo "ÉCHEC : $option devrait borner la réponse UDP à 1232 octets." >&2
		exit 1
	fi
done

echo
echo "== 8. Limitation de débit et parallélisme (passerelle) =="
# Rafale interne au réseau docker : la limite est globale (200 req/s, rafale
# 400) car derrière Tor tous les clients partagent la même IP source.
rejets="$(docker exec tordns-passerelle sh -c 'seq 1 800 | xargs -P 40 -I{} sh -c "wget -q -O /dev/null --header=\"Accept: application/dns-json\" \"http://127.0.0.1:8053/dns-query?name=example.com&type=A\" 2>/dev/null || echo KO"' \
	| grep -c '^KO$' || true)"
echo "Rafale de 800 requêtes : $rejets rejetées (HTTP 429)."
if [ "$rejets" -eq 0 ]; then
	echo "ÉCHEC : aucune requête rejetée, la limitation de débit ne s'applique pas." >&2
	exit 1
fi
apres="$(docker exec tordns-passerelle wget -q -O - --header='Accept: application/dns-json' \
	'http://127.0.0.1:8053/dns-query?name=example.com&type=A' | head -c 1)"
case "$apres" in
'{') echo "Après la rafale, le service répond de nouveau normalement." ;;
*)
	echo "ÉCHEC : le service ne se rétablit pas après la rafale." >&2
	exit 1
	;;
esac

echo
echo "== 9. Isolation des conteneurs (capacités, lecture seule, seccomp) =="
for c in tordns-unbound tordns-passerelle tordns-caddy tordns-tor; do
	capacites="$(docker inspect "$c" --format '{{json .HostConfig.CapDrop}}')"
	lecture_seule="$(docker inspect "$c" --format '{{.HostConfig.ReadonlyRootfs}}')"
	pids="$(docker inspect "$c" --format '{{.HostConfig.PidsLimit}}')"
	memoire="$(docker inspect "$c" --format '{{.HostConfig.Memory}}')"
	options="$(docker inspect "$c" --format '{{json .HostConfig.SecurityOpt}}')"
	seccomp="$(docker exec "$c" sh -c 'grep -c "^Seccomp:[[:space:]]*2" /proc/self/status' 2>/dev/null || echo 0)"
	ajoutees="$(docker inspect "$c" --format '{{len .HostConfig.CapAdd}}')"
	if [ "$capacites" != '["ALL"]' ] || [ "$lecture_seule" != "true" ] \
		|| [ "$pids" -le 0 ] || [ "$memoire" -le 0 ] \
		|| ! printf '%s' "$options" | grep -q 'no-new-privileges' || [ "$seccomp" -lt 1 ]; then
		echo "ÉCHEC : $c mal isolé (CapDrop=$capacites ReadOnly=$lecture_seule Pids=$pids Mem=$memoire Opt=$options Seccomp=$seccomp)" >&2
		exit 1
	fi
	echo "OK : $c — cap-drop ALL ($ajoutees ajoutée(s)), racine en lecture seule, seccomp actif, $((memoire / 1048576)) Mio, $pids pids."
done
# AppArmor n'est appliqué que si le noyau hôte le fournit (docker-default).
if docker exec tordns-passerelle sh -c 'cat /proc/self/attr/current' >/dev/null 2>&1; then
	echo "AppArmor : $(docker exec tordns-passerelle cat /proc/self/attr/current)"
else
	echo "AppArmor : non exposé par ce noyau (profil docker-default appliqué sinon)."
fi

echo
echo "== 10. Sonde de santé anonyme =="
sante="$(tor_curl -sS --max-time 90 -w '\n%{http_code}' "http://$onion/healthz")"
code_sante="$(printf '%s' "$sante" | tail -1)"
corps_sante="$(printf '%s' "$sante" | head -1)"
echo "GET /healthz via Tor -> HTTP $code_sante, corps: $corps_sante"
if [ "$code_sante" != "200" ] || [ "$corps_sante" != "ok" ]; then
	echo "ÉCHEC : la sonde de santé ne répond pas correctement." >&2
	exit 1
fi
