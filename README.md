# TorDNS — résolveur DNS public en service caché Tor (projet confié à Freebuff, 22/11/2026)

But : un résolveur DNS récursif public, sans journal, joignable UNIQUEMENT en .onion (Tor ne
transporte pas l'UDP → DoH, RFC 8484), puis des applications clientes avec Tor embarqué.

## Architecture
Serveur : Tor (service caché v3) → Caddy/Nginx (HTTP, /dns-query) → passerelle DoH → Unbound
(récursif depuis les racines, DNSSEC, aucun forward, aucun journal des requêtes, 127.0.0.1).
Client : OS (UDP 127.0.0.1:53 ou VpnService Android) → relais DNS local avec cache → Tor
embarqué (arti ou tor, SOCKS5) → .onion/dns-query.

## Missions (une à la fois, preuve exigée à chaque fois)
1. `serveur/` : docker-compose Unbound + passerelle DoH + Caddy + Tor, tout en local, sans
   journal. Preuve : `dig @127.0.0.1 -p 5335 example.com +dnssec` et une requête DoH en local.
2. Tor v3 : service caché vers Caddy. Preuve : requête DoH via `curl --socks5-hostname
   127.0.0.1:9050 http://<onion>/dns-query?dns=...` (adresse JAMAIS commitée, clés hors dépôt).
3. Durcissement : limites de débit, refus de l'ANY, taille de réponse, pas de récursion ouverte
   hors DoH, supervision (santé sans données de requêtes).
4. `client-linux/` : relais DNS local (Go ou Rust) + cache + SOCKS5 Tor ; Preuve : `dig
   @127.0.0.1` résolu via l'onion, cache vérifié (2e requête < 5 ms).
5. `client-android/` : VpnService qui intercepte le port 53, arti embarqué.
6. Windows plus tard.

## Règles
- Aucun secret, aucune clé .onion, aucune adresse .onion de prod dans le dépôt.
- Rien ne se déploie ni ne se publie sans Gary. Pas de VPS touché par l'agent.
- Messages et docs en français.
