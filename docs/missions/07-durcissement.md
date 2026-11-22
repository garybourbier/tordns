# Mission 7 — Durcissement relevé à la relecture du 22/11

Relecture de Claude après les missions 1 à 6. Rien de neuf à inventer : corriger ce qui est
écrit ici, le prouver, et remettre le README d'accord avec le code.

## 1. Limite de débit par circuit Tor (aujourd'hui globale)

Constat : `serveur/passerelle/main.go` applique UNE limite pour tout le serveur
(`LIMITE_REQ_S=200`). Un seul client abusif l'épuise et bloque tout le monde. Le README promet
une limite « par circuit dans Caddy » : c'est faux aujourd'hui.

À faire :
- `torrc` : `HiddenServiceExportCircuitID haproxy` sur le service caché → Tor envoie un en-tête
  PROXY v2 dont l'adresse source encode l'identifiant de circuit.
- Le point d'entrée HTTP (Caddy ou la passerelle directement, au choix argumenté dans le
  commit) lit cet en-tête ; la passerelle tient un seau à jetons **par circuit** (table bornée
  en taille, entrées expirées purgées, rien d'écrit sur disque), en plus d'un plafond global.
- Valeurs par défaut raisonnables et réglables par `.env`.

## 2. Défense contre les inondations du service caché

- `HiddenServicePoWDefensesEnabled 1` (Tor ≥ 0.4.8 : vérifier la version de l'image et la
  monter si besoin).
- `HiddenServiceMaxStreams 64` et `HiddenServiceMaxStreamsCloseCircuit 1` (valeurs à justifier).
- Noter dans le README que la PoW est à revérifier derrière Onionbalance (mission 9).

## 3. Le Tor du serveur n'a pas besoin de port SOCKS

`serveur/tor/torrc` ouvre `SocksPort 0.0.0.0:9050`, publié sur 127.0.0.1. Un service caché
n'en a pas l'usage : `SocksPort 0`, retirer la publication du port dans `docker-compose.yml`.
Si `verifier.sh` s'en servait pour tester, lui donner un Tor client séparé, éphémère, propre
au test.

## 4. Vanguards

Un service caché public et durable est exposé à la découverte de ses gardes. Activer la
protection : `VanguardsLiteEnabled 1` (intégré à Tor ≥ 0.4.7) au minimum ; dire dans le
README pourquoi le module complet `vanguards` est ou n'est pas ajouté.

## 5. Preuve de bout en bout du serveur

`serveur/scripts/verifier.sh` ne prouve pas le chemin complet. Ajouter
`scripts/verifier-m07.sh` qui :
- monte la stack, attend la publication du service caché ;
- envoie une vraie requête DoH **par le .onion** (Tor client de test) et vérifie la réponse
  (`example.com` A, et un domaine DNSSEC avec le drapeau AD, et un domaine à signature cassée
  type `dnssec-failed.org` qui doit rendre SERVFAIL) ;
- vérifie qu'un client qui dépasse sa limite est refusé pendant qu'un second circuit passe ;
- vérifie qu'aucun conteneur n'a écrit de nom de domaine demandé dans ses journaux
  (`docker logs` de chaque service, recherche du nom testé).

## 6. README vrai

Le README dit « Caddy / Nginx » et « doh-server » : décrire ce qui existe (Caddy + passerelle
Go maison), l'état réel de chaque client (prouvé / non prouvé), et la protection réelle
contre l'abus.

## Fini quand

`scripts/verifier-m07.sh` passe en entier, sortie dans le message de commit ; README à jour ;
aucun secret ni adresse réelle versionnés.
