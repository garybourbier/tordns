# TorDNS — serveur (Mission 1)

Stack locale docker-compose : un résolveur DNS récursif validant DNSSEC, une
passerelle DoH, un front HTTP et un client Tor. Rien n'est publié ailleurs que
sur `127.0.0.1`, rien n'est journalisé, aucun secret n'est nécessaire pour la
Mission 1.

## Architecture

```
dig (ou un client DoH)
   │
   ├── UDP/TCP 127.0.0.1:5335 ─────────────────┐
   │                                           ▼
   └── HTTP 127.0.0.1:8080 ──► Caddy ──► passerelle DoH ──► Unbound
                               (sans log)   (sans log)      (récursif racines,
                                                             DNSSEC, sans log)
```

| Service     | Image                    | Rôle                                                        | Exposition hôte        |
|-------------|--------------------------|-------------------------------------------------------------|------------------------|
| `unbound`   | `tordns/unbound:local`   | récursion depuis les racines, validation DNSSEC obligatoire | `127.0.0.1:5335` UDP+TCP |
| `passerelle`| `tordns/passerelle:local`| DoH RFC 8484 → DNS filaire vers Unbound                     | aucune                 |
| `caddy`     | `caddy:2-alpine`         | front HTTP `/dns-query`, HTTP en clair (Tor chiffre)         | `127.0.0.1:8080`       |
| `tor`       | `tordns/tor:local`       | client Tor (SOCKS interne), prêt pour la Mission 2          | aucune                 |

Le réseau docker dédié `172.28.53.0/24` est le seul autorisé par Unbound :
`access-control` refuse tout le reste, donc pas de récursion ouverte.

## Choix de sécurité

- **Aucun forward** : Unbound part des serveurs racine (`unbound/root.hints`) et
  valide DNSSEC avec `auto-trust-anchor-file` (ancre initialisée au démarrage
  depuis la clé racine intégrée au binaire, sans réseau).
- **DNSSEC obligatoire** : les réponses non validables donnent SERVFAIL ;
  les réponses validées portent le bit `AD` (visible dans les preuves).
- **Zéro journal de requêtes** :
  - Unbound : `verbosity: 0`, `log-queries: no`, `log-replies: no`,
    `use-syslog: no`, aucun `logfile` ;
  - passerelle : ne journalise rien, `http.Server.ErrorLog` jeté ;
  - Caddy : `log { output discard }`, pas de journal d'accès, `admin off` ;
  - docker : `logging.driver: none` pour ces trois services (aucun journal
    lisible, rien n'est conservé sur disque).
  - Tor conserve uniquement ses messages de démarrage/avertissement
    (`Log warn stdout`, `SafeLogging 1`), jamais de données de requêtes.
- **Aucune métadonnée client transmise** : Caddy supprime `X-Forwarded-*` et
  `X-Real-IP` avant la passerelle.
- **Ports** : Unbound et Caddy ne sont publiés que sur `127.0.0.1`. La
  passerelle et Tor ne publient rien.
- **Secrets** : aucun nécessaire ici. Les clés du service caché v3 de la
  Mission 2 vivront dans `serveur/tor/keys/`, ignoré par git, et aucune adresse
  `.onion` de production ne sera commitée.

## Démarrage

```bash
cd serveur
docker compose up -d --build
docker compose ps          # unbound doit être « healthy »
```

Arrêt : `docker compose down` (ajouter `-v` pour effacer les volumes).

## Preuves (Mission 1)

```bash
cd serveur
./scripts/verifier.sh
```

Le script exécute :

1. **Récursif local + DNSSEC** :
   `dig @127.0.0.1 -p 5335 example.com A +dnssec` → `status: NOERROR`,
   drapeaux `qr rd ra ad`, RRSIG présent dans la réponse.
   L'hôte n'ayant pas `dig` installé, le script utilise celui de l'image
   Unbound en réseau hôte (`docker run --network host --entrypoint dig …`) :
   la requête part bien vers `127.0.0.1:5335`. Sur une machine avec
   `bind-tools`, la commande `dig @127.0.0.1 -p 5335 example.com +dnssec`
   fonctionne telle quelle.
2. **DoH filaire (RFC 8484)** : `POST http://127.0.0.1:8080/dns-query` avec
   `Content-Type: application/dns-message` et une requête `example.com A`
   (EDNS0 DO) → `HTTP 200`, réponse DNS complète, ID conservé, bit `AD` levé.
3. **DoH lisible** : `GET /dns-query?name=example.com&type=A` avec
   `Accept: application/dns-json` → JSON avec `"Status":0` et `"AD":true`.
4. **Récursion fermée** : Unbound ne répond que sur l'adresse publiée en
   `127.0.0.1` et le réseau docker dédié.

Exemple de sortie :

```
;; flags: qr rd ra ad; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 1
example.com.  300  IN  A  104.20.23.154
example.com.  300  IN  A  172.66.147.243
example.com.  300  IN  RRSIG  A 13 2 300 ...
...
HTTP 200 — 179 octets, ID de réponse: 1234 (attendu 1234), drapeaux: 0x81a0
DNSSEC validé par Unbound : bit AD présent dans la réponse DoH.
{"Status":0,"TC":false,"RD":true,"RA":true,"AD":true,"CD":false,...}
```

## Requête DoH manuelle

```bash
# Chemin filaire (RFC 8484), réponse binaire :
curl -sS -H 'content-type: application/dns-message' \
     -H 'accept: application/dns-message' \
     --data-binary @requete.bin \
     http://127.0.0.1:8080/dns-query -o reponse.bin

# Chemin JSON lisible :
curl -sS -H 'accept: application/dns-json' \
     'http://127.0.0.1:8080/dns-query?name=example.com&type=A'
```

## Détail des fichiers

- `docker-compose.yml` — orchestration, réseau privé, ports, journaux.
- `unbound/` — `unbound.conf` (récursion, DNSSEC, zéro log), `root.hints`,
  `Dockerfile`, `entrypoint.sh`.
- `passerelle/` — passerelle DoH en Go, sans dépendance externe
  (`main.go`), `Dockerfile` multi-étapes.
- `caddy/Caddyfile` — routage `/dns-query`, journalisation jetée.
- `tor/` — `torrc` client minimal, `Dockerfile`.
- `scripts/verifier.sh` — preuves automatisées de la Mission 1.

## Limites et suite

- La Mission 1 ne crée pas de service caché : le conteneur Tor est un client
  prêt pour la Mission 2. Le port SOCKS 9050 de l'hôte étant déjà utilisé par
  le Tor du système, aucun port Tor n'est publié.
- Mission 2 : `HiddenServiceDir /var/lib/tor/keys` (volume hors git),
  `HiddenServicePort 80 caddy:8080`, adresse `.onion` jamais commitée.
- Mission 3 : limites de débit, refus de l'ANY, taille de réponse bornée,
  supervision sans données de requêtes.
