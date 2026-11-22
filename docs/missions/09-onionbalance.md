# Mission 9 — Contrôleur Onionbalance : une adresse, plusieurs nœuds

But : une adresse `.onion` **maîtresse** qui répartit sur les nœuds cœur (les 3 VPS de Gary),
et qui continue de répondre quand un nœud tombe.

## À livrer

- `controleur/` (docker-compose séparé, à faire tourner sur un hôte qui n'est PAS un nœud) :
  - un Tor + `onionbalance` (v3, version épinglée) ;
  - la clé maîtresse dans `/var/lib/tordns-controleur/` (0700, ignorée par git), générée par
    `controleur/scripts/creer-maitresse.sh`, avec une procédure écrite de sauvegarde chiffrée
    hors ligne (c'est la clé qui fait l'identité publique du service) ;
  - `controleur/pools/coeur.txt` (hors dépôt ; un exemple `coeur.txt.example`) : une adresse
    d'instance par ligne ; le fichier de configuration d'Onionbalance en est généré.
- Côté nœud : `installer.sh --maitresse <adresse>` (mission 8) suffit pour qu'un nœud rejoigne.
- Documentation `docs/redondance.md` : schéma, ajout / retrait d'un nœud, perte d'un VPS,
  perte du contrôleur (le service continue jusqu'à l'expiration du descripteur maître,
  durée à mesurer et à écrire), rotation de la clé maîtresse.

## À mesurer et écrire tel quel

- Combien de nœuds tiennent dans le descripteur maître (limite de 20 points d'introduction).
- Délai entre l'arrêt d'un nœud et le moment où les clients n'y sont plus envoyés.
- La PoW (mission 7) fonctionne-t-elle derrière Onionbalance ? Si non, le dire et proposer.

## Preuve (`scripts/verifier-m09.sh`)

Trois nœuds sur la même machine de test (trois projets compose, trois clés d'instance) + un
contrôleur, sur le vrai réseau Tor : requêtes DoH répétées par l'adresse maîtresse ; arrêt
d'un nœud ; les requêtes continuent d'aboutir. Sortie dans le commit.
