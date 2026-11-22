# TorDNS — serveur (Missions 1 à 3, durcies en Mission 7)

Stack locale docker-compose : résolveur DNS récursif validant DNSSEC, passerelle
DoH et front HTTP, exposés **exclusivement** en service caché Tor v3. Aucun port
DNS, DoH ou SOCKS n'est publié sur l'hôte : les preuves utilisent un client Tor
séparé et éphémère. Zéro journal de requêtes, aucune clé dans le dépôt,
conteneurs durcis et limite de débit **par circuit Tor**.

## Architecture

```
Clients Tor / DoH
   │  chiffré de bout en bout dans un circuit Tor
   ▼
Service caché v3 (conteneur tor, SocksPort 0)
   │  PROXY v2 : l'adresse source encode l'identifiant de circuit
   ▼
Caddy :8080  ──►  passerelle DoH :8053  ──►  Unbound :5335
   │                (seau par circuit)          │  réseau `sortie`
   │                                             ▼
   │                                   racines DNS + autorités TLD
   └── aucun port publié

Client Tor de test (profil `test`, sans port publié)
   └── SOCKS 127.0.0.1:9050 dans son conteneur ──► .onion
```

| Service      | Image                     | Rôle                                                | Ports publiés |
|--------------|---------------------------|-----------------------------------------------------|---------------|
| `tor`        | `tordns/tor:local`        | service caché v3 → Caddy, **sans SOCKS**            | aucun         |
| `tor-client` | `tordns/tor-client:test`  | client SOCKS éphémère pour les preuves (profil test)| aucun         |
| `caddy`      | `caddy:2-alpine`          | front HTTP, lit le PROXY v2 (IP fixe `172.28.53.20`)| aucun         |
| `passerelle` | `tordns/passerelle:local` | DoH RFC 8484 → DNS filaire, limite par circuit       | aucun         |
| `unbound`    | `tordns/unbound:local`    | récursion racines + validation DNSSEC obligatoire    | aucun         |

Deux réseaux Docker :

- `dns` (`172.28.53.0/24`, `internal: true`) : Unbound, passerelle, Caddy, Tor
  et le client de test. Aucune sortie Internet possible depuis ce réseau.
- `sortie` : uniquement Unbound (récursion), Tor (circuits) et le client de
  test (bootstrap). Le trafic DNS de résolution sort par là, jamais par le
  réseau privé.

## Choix de sécurité

- **Un seul point d'entrée distant** : l'adresse `.onion`. Ni Unbound ni Caddy
  ne sont publiés sur l'hôte ; `docker port` ne renvoie rien pour eux.
- **Récursion fermée** : Unbound interroge directement les racines
  (`root.hints`), sans forward, et n'accepte que `172.28.53.0/24` (réseau
  `dns`) ; le réseau `sortie` et l'hôte sont refusés.
- **DNSSEC obligatoire** : réponses non validables → SERVFAIL ; les réponses
  validées portent `AD` (vérifié de bout en bout à travers Tor).
- **Zéro journal de requêtes** :
  - Unbound : `verbosity: 0`, `log-queries/replies: no`, aucun `logfile` ;
  - passerelle : aucune écriture, `ErrorLog` jeté ;
  - Caddy : `log { output discard }`, pas de journal d'accès, `admin off` ;
  - docker : `logging.driver: none` sur Unbound, passerelle et Caddy ;
  - Tor : `Log warn stdout` + `SafeLogging 1`, jamais le contenu des requêtes.
- **Limite par circuit, pas par IP** : Tor exporte le circuit dans un en-tête
  PROXY v2 (`HiddenServiceExportCircuitID haproxy`). Caddy le lit et transmet
  l'adresse source à la passerelle via `X-TorDNS-Circuit` ; la passerelle tient
  un seau à jetons par circuit, en mémoire, table bornée (`LIMITE_CIRCUITS_MAX`)
  et purge des entrées inactives (`LIMITE_CIRCUIT_TTL`). Un plafond global
  reste appliqué. Aucune écriture disque.
- **Anti-inondation du service caché** : PoW (`HiddenServicePoWDefensesEnabled`),
  64 flux simultanés par circuit (`HiddenServiceMaxStreams 64`, fermeture du
  circuit au-delà) et vanguards intégrés (`VanguardsLiteEnabled 1`).
- **Aucune métadonnée client** : Caddy supprime `X-Forwarded-*` et `X-Real-IP`
  et ne transmet que l'identifiant de circuit, immédiatement consommé par la
  passerelle.
- **Clés du service caché hors dépôt** : générées par Tor dans le volume docker
  `tor-data` (permissions `0700`), jamais versionnées. Sauvegarde explicite et
  chiffrable via `scripts/gestion-cles.sh sauvegarder` (dossier `cles-onion/`,
  ignoré par git, `0600`).
- **Aucune adresse `.onion` de production dans le dépôt** : `.gitignore` couvre
  `serveur/cles-onion/`, `*.onion`, `*.key`, `.env*`.

## Durcissement (Mission 3)

- **Anti-amplification DNS** : Unbound refuse le type `ANY` (`deny-any: yes`,
  réponse `NOTIMP`), borne les réponses UDP à 1232 octets (`edns-buffer-size`
  et `max-udp-size`) et n'accepte que le réseau docker privé.
- **Anti-empoisonnement** : `use-caps-for-id: yes` (casse aléatoire 0x20),
  `harden-algo-downgrade`, `harden-unknown-additional`, `qname-minimisation`.
- **Limitation de débit** : la passerelle applique d'abord un seau par circuit
  (`LIMITE_CIRCUIT_REQ_S` = 20 req/s, rafale `LIMITE_CIRCUIT_RAFALE` = 40),
  puis un plafond global (`LIMITE_REQ_S` = 200 req/s, rafale 400) et borne le
  parallélisme (`MAX_CONCURRENTS` = 64). Au-delà : `HTTP 429` + `Retry-After`.
  Un circuit abusif ne consomme pas le quota des autres ; le plafond global
  protège d'une attaque répartie sur de nombreux circuits.
- **Isolation des conteneurs** : `cap_drop: ALL`, `no-new-privileges`, système
  de fichiers racine en lecture seule (`read_only`, avec `tmpfs` pour `/tmp`),
  `pids_limit: 256`, mémoire bornée (128 ou 256 Mio). Le profil seccomp par
  défaut de Docker est actif (`Seccomp: 2`, un filtre) ; AppArmor
  « docker-default » s'applique si le noyau hôte le fournit.
  Deux exceptions minimales : Unbound garde `CHOWN/DAC_OVERRIDE/SETUID/SETGID`
  pour préparer son ancre DNSSEC puis passer à l'utilisateur `unbound` — sans
  elles, `execve` d'un binaire portant une capacité de fichier échoue.
- **Sonde de santé anonyme** : `GET /healthz` sur Caddy → passerelle → Unbound
  effectue une résolution fixe (`example.com A`) et répond `ok` / `503`. Aucune
  entrée de journal, aucune donnée client. Utilisée par les `healthcheck`
  Docker de la passerelle et de Caddy ; Tor est vérifié par la présence de son
  fichier `hostname`, une fois le service publié.

## Démarrage

```bash
cd serveur
cp .env.example .env       # optionnel : limites de débit
docker compose up -d --build
docker compose ps          # unbound/passerelle/caddy/tor selon l'état
docker compose --profile test up -d --build tor-client  # preuves
./scripts/verifier.sh
```

Aucun SOCKS n'est publié sur l'hôte : le client de test parle au .onion depuis
son propre conteneur (`docker exec tordns-tor-client curl ...`). Le profil
`test` n'est pas démarré par un `docker compose up` ordinaire.

Arrêt : `docker compose down`. **Attention** : `docker compose down -v`
supprime le volume `tor-data`, donc les clés et l'adresse `.onion`. Faites une
sauvegarde avant (`./scripts/gestion-cles.sh sauvegarder`).

## Gestion des clés du service caché

```bash
cd serveur
./scripts/gestion-cles.sh adresse      # affiche l'adresse .onion courante
./scripts/gestion-cles.sh sauvegarder  # copie les clés dans cles-onion/ (0600)
./scripts/gestion-cles.sh verifier     # vérifie qu'aucune clé n'est suivie par git
```

Restauration sur une autre machine : arrêter la stack, remettre le contenu de
`cles-onion/` dans le volume `tor-data` (par exemple
`docker run --rm -v tordns_tor-data:/var/lib/tor -v "$PWD/cles-onion":/sauvegarde:ro alpine sh -c 'cp -a /sauvegarde/. /var/lib/tor/hidden_service/ && chown -R 100:101 /var/lib/tor'`),
puis redémarrer. L'adresse `.onion` reste identique.

## Preuves (Missions 1 à 3)

```bash
cd serveur
./scripts/verifier.sh
```

1. **Récursif + DNSSEC** : `dig @127.0.0.1 -p 5335 example.com A +dnssec`
   exécuté dans le conteneur Unbound → `NOERROR`, drapeaux `qr rd ra ad`,
   RRSIG présent.
2. **Adresse `.onion`** du service v3, lue depuis le volume Tor.
3. **DoH filaire via Tor** : requête POST envoyée par le client de test
   (`docker exec tordns-tor-client curl --socks5-hostname 127.0.0.1:9050 ...`)
   → `HTTP 200`, réponse DNS complète, ID conservé, bit `AD` levé.
4. **DoH JSON via Tor** → `"Status":0`, `"AD":true`.
5. **Cloisonnement** : `docker port` vide pour Unbound, passerelle, Caddy **et
   Tor** ; réseau `dns` interne.
6. **Dépôt propre** : aucune clé ni adresse `.onion` suivie par git.
7. **Durcissement** : `ANY example.com` → `NOTIMP`, `edns-buffer-size` et
   `max-udp-size` = 1232.
8. **Plafond global** : rafale de 800 requêtes internes → plusieurs centaines
   de `429`, puis le service répond normalement.
9. **Isolation** : `CapDrop=["ALL"]`, racine en lecture seule, `pids_limit` et
   mémoire bornés, `no-new-privileges`, seccomp actif pour les 4 conteneurs.
10. **Sonde** : `GET /healthz` via Tor → `HTTP 200`, corps `ok`.

## Preuves Mission 7

```bash
cd ..          # racine du dépôt
./scripts/verifier-m07.sh
```

Le script vérifie les versions minimales, le `torrc` effectif, l'absence de
SOCKS sur le nœud, DNSSEC et SERVFAIL via le `.onion`, la limite par circuit à
travers Caddy (deux circuits PROXY distincts) et l'absence du nom testé dans
les journaux.

Exemple observé (2026-11-22) :

```
Tor 0.4.9.17, Caddy 2.11.4
SocksPort 0
HiddenServiceExportCircuitID haproxy
HiddenServicePoWDefensesEnabled 1
HiddenServiceMaxStreams 64
HiddenServiceMaxStreamsCloseCircuit 1
VanguardsLiteEnabled 1
Configuration Tor valide.
Aucune écoute SOCKS et aucun port publié par le nœud.

example.com A : HTTP 200, 179 octets, ID 1234, drapeaux 0x81a0
AD présent : DNSSEC validé de bout en bout.
dnssec-failed.org A : HTTP 200, rcode=2 (attendu 2/SERVFAIL)

Circuit A : 80 requêtes, 33 refusées (HTTP 429).
Circuit B : HTTP/1.1 200 OK

tordns-unbound : driver=none (aucun journal conservé, LogPath='').
tordns-passerelle : driver=none (aucun journal conservé, LogPath='').
tordns-caddy : driver=none (aucun journal conservé, LogPath='').
tordns-tor : driver=json-file, aucune occurrence du nom.
tordns-tor-client : driver=none (aucun journal conservé, LogPath='').
```

Référence `verifier.sh` (même exécution) :

```
HTTP 200 — 179 octets, ID de réponse: 1234 (attendu 1234), drapeaux: 0x81a0
DNSSEC validé par Unbound : bit AD présent dans la réponse DoH.
{"Status":0,...,"AD":true,...}
OK : réseau docker privé interne, aucun port DNS/DoH publié.
ANY example.com -> NOTIMP (attendu NOTIMP ou REFUSED)
edns-buffer-size = 1232
max-udp-size = 1232
Rafale de 800 requêtes : 370 rejetées (HTTP 429).
OK : tordns-unbound — cap-drop ALL (4 ajoutée(s)), racine en lecture seule, ...
GET /healthz via Tor -> HTTP 200, corps: ok
```

## Détail des fichiers

- `docker-compose.yml` — services, réseaux `dns`/`sortie`, profil `test`, journaux.
- `.env.example` — limites par circuit, plafond global, parallélisme.
- `unbound/` — `unbound.conf` (récursion, DNSSEC, zéro log), `root.hints`,
  `Dockerfile`, `entrypoint.sh`.
- `passerelle/` — passerelle DoH Go sans dépendance (`main.go`), seau par
  circuit et tests (`main_test.go`), `Dockerfile`.
- `caddy/Caddyfile` — routage `/dns-query` et `/healthz`, PROXY protocol,
  en-tête de circuit, journalisation jetée.
- `tor/torrc` — service caché v3 (`172.28.53.20:8080`), `SocksPort 0`,
  export du circuit, PoW, flux bornés, vanguards.
- `tor-client/` — client SOCKS éphémère des preuves (profil `test`).
- `scripts/verifier.sh` — preuves des trois missions (10 sections).
- `scripts/requete-proxy.sh` — requête HTTP précédée d'un PROXY v1 de test.
- `scripts/gestion-cles.sh` — adresse, sauvegarde et contrôle des clés.
- `../scripts/verifier-m07.sh` — preuves de la Mission 7.

## Limites et suite

- Le service caché, le client de test et la limite par circuit sont testés
  localement uniquement ; aucun déploiement distant.
- **PoW derrière Onionbalance** : la défense par preuve de travail est réglée
  par descripteur. Son comportement derrière Onionbalance n'est pas vérifié
  ici ; c'est un point de la Mission 9, pas une affirmation du README.
- La table des circuits est en mémoire : un redémarrage remet les compteurs à
  zéro, et un circuit inactif expire après `LIMITE_CIRCUIT_TTL` (120 s).
- Seccomp est le profil par défaut de Docker (pas de profil sur mesure) ;
  AppArmor n'est pas exposé par le noyau de cette machine de test.
- La sonde `/healthz` résout `example.com A` toutes les 30 s : elle génère un
  peu de trafic sortant, sans jamais journaliser la requête.
