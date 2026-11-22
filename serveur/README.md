# TorDNS — serveur (Missions 1 & 2)

Stack locale docker-compose : résolveur DNS récursif validant DNSSEC, passerelle
DoH et front HTTP, exposés **exclusivement** en service caché Tor v3. Aucun port
DNS ou DoH n'est publié sur l'hôte ; seul le SOCKS local (loopback) sert aux
tests. Zéro journal de requêtes, aucune clé dans le dépôt.

## Architecture

```
Client Tor / DoH
   │  chiffré de bout en bout dans un circuit Tor
   ▼
Service caché v3 (conteneur tor)  ── 127.0.0.1:19050 (SOCKS, tests locaux)
   │  réseau docker privé `dns` (internal: true)
   ▼
Caddy :8080  ──►  passerelle DoH :8053  ──►  Unbound :5335
   │                                             │  réseau `sortie`
   │                                             ▼
   │                                   racines DNS + autorités TLD
   └── aucun port publié (uniquement Tor publie, sur loopback)
```

| Service     | Image                     | Rôle                                                | Ports publiés          |
|-------------|---------------------------|-----------------------------------------------------|------------------------|
| `tor`       | `tordns/tor:local`        | service caché v3 → Caddy, client SOCKS de test      | `127.0.0.1:19050`      |
| `caddy`     | `caddy:2-alpine`          | front HTTP `/dns-query` (IP fixe `172.28.53.20`)     | aucun                  |
| `passerelle`| `tordns/passerelle:local` | DoH RFC 8484 → DNS filaire vers Unbound             | aucun                  |
| `unbound`   | `tordns/unbound:local`    | récursion racines + validation DNSSEC obligatoire    | aucun                  |

Deux réseaux Docker :

- `dns` (`172.28.53.0/24`, `internal: true`) : Unbound, passerelle, Caddy, Tor.
  Aucune sortie Internet possible depuis ce réseau.
- `sortie` : uniquement Unbound (récursion) et Tor (circuits). Le trafic DNS de
  résolution sort par là, jamais par le réseau privé.

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
- **Aucune métadonnée client** : Caddy supprime `X-Forwarded-*` et `X-Real-IP`.
- **Clés du service caché hors dépôt** : générées par Tor dans le volume docker
  `tor-data` (permissions `0700`), jamais versionnées. Sauvegarde explicite et
  chiffrable via `scripts/gestion-cles.sh sauvegarder` (dossier `cles-onion/`,
  ignoré par git, `0600`).
- **Aucune adresse `.onion` de production dans le dépôt** : `.gitignore` couvre
  `serveur/cles-onion/`, `*.onion`, `*.key`, `.env*`.

## Démarrage

```bash
cd serveur
cp .env.example .env       # optionnel, pour changer TOR_SOCKS_PORT
docker compose up -d --build
docker compose ps          # unbound « healthy », tor « Up »
./scripts/verifier.sh
```

Si le port 9050 est déjà utilisé par un Tor système (cas de cette machine),
mettre `TOR_SOCKS_PORT=19050` dans `serveur/.env` (fichier ignoré par git) :
c'est ce port loopback que les tests curl utilisent.

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

## Preuves (Missions 1 & 2)

```bash
cd serveur
./scripts/verifier.sh
```

1. **Récursif + DNSSEC** : `dig @127.0.0.1 -p 5335 example.com A +dnssec`
   exécuté dans le conteneur Unbound → `NOERROR`, drapeaux `qr rd ra ad`,
   RRSIG présent.
2. **Adresse `.onion`** du service v3, lue depuis le volume Tor.
3. **DoH filaire via Tor** :
   `curl --socks5-hostname 127.0.0.1:19050 -H 'content-type: application/dns-message' --data-binary @requete.bin http://<service>.onion/dns-query`
   → `HTTP 200`, réponse DNS complète, ID conservé, bit `AD` levé.
4. **DoH JSON via Tor** → `"Status":0`, `"AD":true`.
5. **Cloisonnement** : `docker port` vide pour Unbound/passerelle/Caddy,
   réseau `dns` interne.
6. **Dépôt propre** : aucune clé ni adresse `.onion` suivie par git.

Exemple observé (2026-11-22) :

```
;; flags: qr rd ra ad; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 1
example.com. 300 IN A 104.20.23.154
example.com. 300 IN RRSIG A 13 2 300 ...

.onion = <adresse locale>  (générée localement, jamais commitée)

HTTP 200 — 179 octets, ID de réponse: 1234 (attendu 1234), drapeaux: 0x81a0
DNSSEC validé par Unbound : bit AD présent dans la réponse DoH.
{"Status":0,...,"AD":true,...}
OK : réseau docker privé interne, aucun port DNS/DoH publié.
OK : sauvegarde locale présente et ignorée par git.
```

## Détail des fichiers

- `docker-compose.yml` — services, réseaux `dns`/`sortie`, ports, journaux.
- `.env.example` — port SOCKS local (`TOR_SOCKS_PORT`).
- `unbound/` — `unbound.conf` (récursion, DNSSEC, zéro log), `root.hints`,
  `Dockerfile`, `entrypoint.sh`.
- `passerelle/` — passerelle DoH Go sans dépendance (`main.go`), `Dockerfile`.
- `caddy/Caddyfile` — routage `/dns-query`, journalisation jetée.
- `tor/torrc` — service caché v3 (`172.28.53.20:8080`), SOCKS, zéro fuite.
- `scripts/verifier.sh` — preuves des deux missions.
- `scripts/gestion-cles.sh` — adresse, sauvegarde et contrôle des clés.

## Limites et suite

- Le service caché et le SOCKS sont testés localement uniquement ; aucun
  déploiement distant.
- Le port 9050 de l'hôte est occupé par le Tor système, d'où
  `TOR_SOCKS_PORT=19050` dans le `.env` local. Sur un serveur dédié, 9050
  fonctionne sans réglage.
- Mission 3 : anti-amplification (refus `ANY`, tailles bornées), limitation de
  débit par circuit, profils seccomp/apparmor, sonde de santé anonyme.
