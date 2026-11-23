# TorDNS — client Linux (Mission 4)

Relais DNS local qui rend le service caché TorDNS utilisable par n'importe
quelle application : il écoute le DNS classique sur `127.0.0.1:53` (UDP et TCP),
répond depuis un cache mémoire, et transporte les requêtes manquantes en DoH
(RFC 8484) vers le `.onion` à travers le proxy SOCKS5 d'un démon Tor local.

Aucun paquet DNS n'est émis en clair : le relais n'ouvre qu'une connexion vers
`127.0.0.1:9050` (ou le port configuré). Aucun journal de requête, rien sur
disque.

```
Application / navigateur / OS
   │ UDP ou TCP 127.0.0.1:53
   ▼
tordns-client  ── cache LRU mémoire (TTL respecté, < 1 ms en cache)
   │ DoH POST /dns-query, HTTP/1.1 keep-alive
   ▼
SOCKS5 127.0.0.1:9050  ──►  service caché <adresse>.onion  ──►  Caddy → passerelle → Unbound
```

## Construction et lancement

```bash
cd client-linux
go build -o tordns-client .
TORDNS_ONION=<adresse>.onion ./tordns-client
```

Le port 53 est privilégié. Trois options :

1. **systemd** (recommandé) : l'unité fournie accorde uniquement
   `CAP_NET_BIND_SERVICE` au binaire (voir plus bas).
2. `sudo setcap cap_net_bind_service=+ep ./tordns-client` puis exécution
   normale.
3. Écoute sur un port haut pour les tests : `-ecoute 127.0.0.1:15353`
   (c'est ce que fait `scripts/verifier.sh`, aucun privilège requis).

## Configuration

| Option           | Variable          | Défaut           | Rôle                                        |
|------------------|-------------------|------------------|---------------------------------------------|
| `-onion`         | `TORDNS_ONION`    | — (obligatoire)  | adresse du service caché TorDNS             |
| `-ecoute`        | `TORDNS_ECOUTE`   | `127.0.0.1:53`   | adresse et port d'écoute UDP **et** TCP     |
| `-socks`         | `TORDNS_SOCKS`    | `127.0.0.1:9050` | proxy SOCKS5 du démon Tor                   |
| `-cache`         | `TORDNS_CACHE`    | `4096`           | nombre maximal d'entrées (LRU)              |
| `-ttl-max`       | —                 | `3600` s         | plafond de mise en cache                    |
| `-delai`         | —                 | `10s`            | délai maximal par requête DoH               |
| `-concurrence`   | —                 | `64`             | requêtes simultanées et taille du pool DoH  |
| `-diagnostic`    | —                 | —                | inspecte les fuites DNS puis quitte         |

Exemple (`/etc/tordns/client.env`, permissions `0600`) :

```sh
TORDNS_ONION=votreadresse.onion
TORDNS_SOCKS=127.0.0.1:9050
TORDNS_ECOUTE=127.0.0.1:53
TORDNS_CACHE=4096
```

Diagnostic des fuites (aucun domaine n'est envoyé) :

```bash
./tordns-client --diagnostic
# [FUITE] resolv.conf utilise le résolveur 192.168.1.1, hors TorDNS…
# [FUITE] systemd-resolved actif (stub 127.0.0.53)…
# [OK] aucune politique DoH d'entreprise détectée ; …
# Bilan : 2 fuite(s) à fermer.   (code de sortie 1)
```

Il inspecte `/etc/resolv.conf` (IPv4, `::1`, stub systemd), les politiques DoH
Firefox/Chrome/Edge et rappelle comment désactiver le DoH des profils. Une
machine corrigée (`nameserver 127.0.0.1`) sort en code 0.

Puis, pour router tout le système vers le relais, `/etc/resolv.conf` :

```
nameserver 127.0.0.1
options edns0 trust-ad
```

## Installation systemd

```bash
sudo install -m 0755 tordns-client /usr/local/bin/
sudo install -d -m 0750 /etc/tordns
sudo install -m 0600 .env.example /etc/tordns/client.env   # puis renseigner l'adresse
sudo install -m 0644 tordns-client.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now tordns-client
systemctl status tordns-client
```

L'unité tourne sous l'utilisateur `tordns` (à créer : `sudo useradd --system
--no-create-home --shell /usr/sbin/nologin tordns`), avec
`CapabilityBoundingSet=CAP_NET_BIND_SERVICE`, `NoNewPrivileges`,
`ProtectSystem=strict` et `PrivateTmp`. Elle suppose un démon Tor local
(`SocksPort 127.0.0.1:9050`) déjà actif.

## Preuves

```bash
cd client-linux
./scripts/verifier.sh          # TORDNS_PORT=15353 par défaut, TORDNS_ONION sinon lue du serveur
# avec le port 53 réel (si privilège disponible) :
sudo TORDNS_PORT=53 ./scripts/verifier.sh
```

Le script construit le relais, le démarre, puis vérifie :

1. **UDP** : `dig @127.0.0.1 -p <port> example.com A +dnssec` → `NOERROR`,
   drapeaux `qr rd ra ad`, RRSIG présent ;
2. **TCP** : `dig +tcp` → mêmes adresses ;
3. **Cache** : seconde requête et lot de 100 requêtes identiques → moyenne
   exigée **< 5 ms** (échec du script sinon) ;
4. **Négatif** : `example.invalid` → `NXDOMAIN` ; les connexions du processus
   pointent vers le SOCKS, jamais vers un résolveur ;
5. **Bilan** : à l'arrêt, nombre de requêtes / hits / erreurs, sans aucun nom
   de domaine dans le journal.

Extrait observé (2026-11-22, port 15353, stack serveur locale) :

```
;; flags: qr rd ra ad; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 1
example.com. 232 IN A 104.20.23.154
example.com. 232 IN RRSIG A 13 2 300 ...
;; Query time: 0 msec
Lot de 100 requêtes mises en cache : moyenne 0.000 ms, maximum 0 ms.
;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN
  via SOCKS :19050
arrêt : 104 requêtes, 101 servies par le cache, 0 erreurs
```

Tests unitaires : `go test ./...` (cache LRU/expiration, TTL positif et négatif,
lecture de noms compressés, bit DO, réécriture d'identifiant, SERVFAIL,
diagnostic sur fixtures, 10 000 paquets hostiles).

## Choix et garanties

- **Zéro fuite** : aucune résolution locale, aucun `net.Resolver` ; tout passe
  par SOCKS5, l'adresse `.onion` est envoyée en nom (ATYP 3) pour que Tor la
  résolve lui-même.
- **Cache correct** : clé = nom (casse normalisée) + type + classe + bit DO ;
  une réponse positive expire au plus petit TTL de la **section réponse**
  (l'autorité ne raccourcit plus le cache) ; NXDOMAIN et NODATA suivent le TTL
  négatif du SOA (minimum du TTL et du champ MINIMUM, RFC 2308), sans SOA elles
  ne sont pas gardées. Plafond 1 h, TTL nul jamais caché, TTL rendu décroissant
  avec l'âge ; réponses tronquées et erreurs jamais cachées.
- **Identifiants** : l'identifiant de transaction du client est réécrit dans la
  réponse ; une réponse dont l'identifiant ne correspond pas est rejetée.
- **Zéro journal** : seuls le démarrage, les erreurs (sans nom de domaine) et
  le bilan d'arrêt sont écrits sur la sortie d'erreur.
- **Connexions** : pool keep-alive vers Tor, une seule reprise en cas de
  connexion morte, saturation au-delà de `-concurrence` (requête abandonnée
  plutôt qu'accumulée).

## Mise à jour signée (Mission 11)

`tordns-client-maj` applique le même manifeste signé que les nœuds : signature
Ed25519 épinglée, version strictement supérieure, expiration, taille et
SHA-256 de la cible `client-linux-amd64`. Le binaire est écrit à côté puis
renommé (atomique) ; si `systemctl restart tordns-client` ou le contrôle
`is-active` échoue, le binaire précédent est remis en place et redémarré.

```bash
cd client-linux
go build -ldflags "-X tordns/manifeste.ClePubliqueEpinglee=<clé hex>" \
    -o tordns-client ./..
go build -ldflags "-X tordns/manifeste.ClePubliqueEpinglee=<clé hex>" \
    -o tordns-client-maj ./cmd/maj
sudo install -m 0755 tordns-client-maj /usr/local/bin/
sudo install -m 0644 tordns-maj-client.service tordns-maj-client.timer /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now tordns-maj-client.timer
```

`/etc/tordns/maj-client.env` :

```sh
TORDNS_MAJ_MANIFESTE=http://<adresse>.onion/maj/manifeste.json
TORDNS_MAJ_SIGNATURE=http://<adresse>.onion/maj/manifeste.json.sig
TORDNS_MAJ_SOCKS=127.0.0.1:9050
TORDNS_MAJ_ETAT=/var/lib/tordns/maj-client.json
TORDNS_MAJ_BINAIRE=/usr/local/bin/tordns-client
```

## DNSSEC et adresses signées (Mission 12)

Le client valide désormais DNSSEC lui-même avec `github.com/miekg/dns` : il
part de la clé racine IANA (20326), construit la chaîne DS/DNSKEY jusqu'à la
zone de la question et vérifie les `RRSIG` de la réponse. Une signature fausse
ou une chaîne rompue donne `SERVFAIL` ; la réponse du nœud n'est jamais
relayée. Trois modes :

```sh
TORDNS_DNSSEC=auto    # défaut : refuse le faux, accepte les zones non signées
TORDNS_DNSSEC=strict  # refuse aussi les zones non signées
TORDNS_DNSSEC=non     # désactive (déconseillé)
```

Les preuves de négation NSEC/NSEC3 vérifient bien les signatures présentes,
mais ne prouvent pas encore cryptographiquement l'absence d'un enregistrement.
C'est écrit comme non prouvé.

L'adresse n'est plus seulement `-onion` : le client lit le dernier
`manifeste.json` vérifié déposé par `tordns-client-maj` dans
`/var/lib/tordns/maj/`. Le réglage `TORDNS_MODE_ADRESSE` vaut `coeur` (défaut),
`secours` (cœur puis communauté) ou `communaute`. En mode `coeur`, une liste
sans adresse cœur ne bascule jamais silencieusement sur un bénévole : le
client retombe sur `TORDNS_ONION`. L'écran et la configuration rappellent que
les nœuds communauté sont des bénévoles non vérifiés.

```sh
TORDNS_MODE_ADRESSE=coeur
TORDNS_ADRESSES=/var/lib/tordns/maj
TORDNS_ONION=<adresse de secours>
```

## Limites

- DNSSEC est validé avec `github.com/miekg/dns` ; la chaîne complète et le
  rejet d'une adresse altérée sont testés hors ligne. Aucun échange avec les
  serveurs racine réels n'est exécuté dans les tests.
- Les preuves de négation NSEC/NSEC3 ne sont pas encore complètes (voir plus
  haut) ; une zone non signée reste acceptée en mode `auto`.
- Le cache est volatil (perdu au redémarrage) et non partagé entre instances.
- Le port 53 de cette machine de test n'est pas ouvrable sans privilège : la
  preuve locale utilise 15353 (5353 est occupé par Avahi/KDE Connect).
- Aucun support Windows/Android ici : c'est l'objet des phases 5 et 6.
