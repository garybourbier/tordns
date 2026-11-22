# Redondance : une adresse, plusieurs nœuds

Une adresse `.onion` **maîtresse** répartit les requêtes DoH sur les nœuds du
pool. Chaque nœud reste un service caché v3 complet (Tor + Caddy + passerelle +
Unbound) avec sa propre adresse d'instance ; le contrôleur Onionbalance recopie
leurs points d'introduction dans un descripteur maître signé par la clé
maîtresse.

```
                 clients (Linux, Android, Windows)
                              │  adresse maîtresse unique
                              ▼
              ┌──────── descripteur maître (Onionbalance) ────────┐
              │  clé maîtresse + liste des instances              │
              └───────┬───────────────┬───────────────┬───────────┘
                      ▼               ▼               ▼
                  nœud A           nœud B           nœud C
              (VPS ou bénévole)  (VPS)            (VPS)
              Tor + Caddy + passerelle + Unbound, chacun avec son .onion
                      ▲               ▲               ▲
                      └──── contrôleur : Tor + onionbalance ────┘
                            (hôte distinct, clé maîtresse, pool)
```

Le contrôleur ne voit **aucune requête DNS** : il ne fait que publier un
descripteur. Les requêtes vont du client directement au nœud choisi par Tor.
Il n'a donc aucun journal à tenir, et le pool ne contient que des adresses
publiques d'instances.

## Mise en place

1. Sur le contrôleur, créer la clé maîtresse (une seule fois) :

   ```sh
   sudo ./controleur/scripts/creer-maitresse.sh
   ```

   Elle écrit `/var/lib/tordns-controleur/maitresse.key` (0600) et
   `maitresse.onion`, dans un dossier 0700, hors dépôt. **La sauvegarder
   avant tout** (voir plus bas) : sans elle, l'identité publique du service est
   perdue.

2. Sur chaque nœud, une commande suffit pour rejoindre le pool :

   ```sh
   sudo ./noeud/installer.sh --maitresse <adresse maîtresse>
   tordns-adresse        # affiche l'adresse d'instance à mettre dans le pool
   ```

   L'installeur est idempotent : relancer avec `--maitresse` ne touche pas aux
   clés ; relancer sans l'option retire la préparation Onionbalance sans
   supprimer l'identité du nœud.

3. Sur le contrôleur, remplir le pool puis démarrer :

   ```sh
   cp controleur/pools/coeur.txt.example controleur/pools/coeur.txt
   $EDITOR controleur/pools/coeur.txt     # une adresse d'instance par ligne
   sudo ./controleur/scripts/demarrer.sh
   ```

   `config.yaml` est régénéré depuis le pool à chaque démarrage. Le pool et les
   clés ne sont jamais versionnés.

## Ajouter un nœud

1. Installer le nœud avec `--maitresse <adresse maîtresse>`.
2. Ajouter son adresse d'instance au pool, une par ligne.
3. `sudo ./controleur/scripts/demarrer.sh` (relance onionbalance).

Les clients continuent d'être servis par les nœuds déjà présents pendant la
mise à jour. Le descripteur maître est réécrit au cycle de publication suivant
d'Onionbalance (contrôle toutes les 5 min, publication immédiate si le jeu de
points d'introduction a changé).

## Retirer un nœud

1. Retirer son adresse du pool.
2. Relancer `demarrer.sh`.
3. Seulement ensuite, désinstaller le nœud (`sudo ./noeud/desinstaller.sh` ;
   les clés sont conservées, leur suppression exige `--supprimer-cles` et la
   confirmation « SUPPRIMER »).

Retirer d'abord du pool évite de laisser des points d'introduction morts dans
le descripteur maître.

## Perte d'un VPS

Le service continue : Tor choisit un point d'introduction parmi ceux du
descripteur maître, et réessaie un autre point quand un nœud ne répond pas.
Onionbalance ne retire l'instance du descripteur qu'après l'avoir considérée
morte : `INSTANCE_DESCRIPTOR_TOO_OLD` vaut **3600 s** dans onionbalance 0.2.4.
Pendant cette heure, des clients peuvent encore être envoyés vers ses points
morts ; ils échouent puis réessaient, d'où une latence dégradée mais un service
maintenu tant qu'il reste des nœuds vivants.

Mesures sur trois nœuds locaux (réseau Tor réel), `scripts/verifier-m09.sh` :

- 63 à 78 secondes pour la première publication de l'adresse maîtresse
  après le démarrage du contrôleur ;
- 10/10 requêtes DoH abouties immédiatement après l'arrêt d'un nœud ;
- 10/10 requêtes encore abouties 5 min après (le descripteur maître
  contenait toujours les points du nœud arrêté : 2 des 6 points) ;
- 10/10 requêtes abouties après l'arrêt complet du contrôleur.

Le descripteur maître mesuré déclare une durée de validité de
180 minutes. C'est la borne haute de survie sans contrôleur
(c'est-à-dire sans republication), à laquelle s'ajoutent les descripteurs déjà
en cache chez les clients ; cette durée n'a **pas** été attendue en entier.

## Perte du contrôleur

Sans contrôleur, plus personne ne republie le descripteur maître, mais celui
déjà publié reste servi par les HSDirs jusqu'à expiration (180 minutes
mesurées). Les clients continuent donc de joindre les nœuds pendant
cette fenêtre, puis le service devient injoignable par l'adresse maîtresse.

La reprise exige **la clé maîtresse et le pool** :

1. restaurer `maitresse.key`, `maitresse.onion` et le pool depuis la sauvegarde
   chiffrée ;
2. relancer `controleur/scripts/creer-maitresse.sh` (il constate la clé et
   n'écrit rien) puis `demarrer.sh` ;
3. vérifier que l'adresse maîtresse est identique (elle dérive de la clé).

Un contrôleur de secours peut tourner ailleurs avec la même clé et le même
pool : la clé ne doit alors être copiée que chiffrée, jamais dans git.

## Sauvegarde chiffrée de la clé maîtresse

La clé maîtresse ne quitte pas le contrôleur en clair. Procédure avec `age`
(recommandée ; GPG avec une clé hors ligne convient aussi) :

```sh
# 1. Sur une machine hors ligne, créer une paire age et garder la clé privée
#    sur un support chiffré, jamais sur le contrôleur.
age-keygen -o tordns-maitresse.agekey

# 2. Sur le contrôleur, chiffrer clé + adresse (+ le pool, non secret mais
#    nécessaire à la reprise).
tar -C /var/lib/tordns-controleur -cf - maitresse.key maitresse.onion \
    | age -r <destinataire-public-age> -o tordns-controleur-$(date +%F).tar.age

# 3. Vérifier la sauvegarde et la faire relire ailleurs.
age -d -i tordns-maitresse.agekey tordns-controleur-2026-11-22.tar.age | tar -tvf -
```

Conserver au moins deux copies sur des supports distincts, hors ligne. Une
restauration se teste sur un dossier jetable (`--donnees`) avant d'en avoir
besoin : c'est le seul moyen de savoir que la sauvegarde est utilisable.

## Rotation de la clé maîtresse

L'adresse maîtresse dérive de la clé : **changer la clé change l'adresse**.
Il n'y a pas de rotation transparente. Procédure :

1. créer une nouvelle clé dans un autre dossier de données ;
2. y rattacher les nœuds (`installer.sh --maitresse <nouvelle adresse>`), ce
   qui remplace leur `ob_config` sans toucher à leur identité d'instance ;
3. publier la nouvelle adresse dans la liste signée des adresses (mission 12) ;
4. garder l'ancien contrôleur en marche pendant la période de recouvrement,
   puis retirer l'ancienne adresse.

Tant que l'ancienne clé existe, l'ancienne adresse peut être ressuscitée : la
détruire (et sa sauvegarde) est une décision explicite.

## Limite du descripteur et diversité

Un descripteur v3 porte au plus **20 points d'introduction**. Onionbalance en
prend **2 par instance** (`N_INTROS_PER_INSTANCE = 2`), soit **10 instances**
au plus par adresse maîtresse. Chaque instance publie 3 points ; les 2 choisis
ne sont pas forcément les mêmes d'une publication à l'autre.

Avec trois nœuds, le descripteur maître mesuré contient 6 points
d'introduction. Au-delà de dix instances, onionbalance
construit un descripteur trop gros ou trop fourni et la publication échoue :
le générateur de pool avertit sans bloquer, et la limite réelle doit être
mesurée sur le réseau avant d'ouvrir l'adresse à plus de nœuds.

Répartir les instances sur des sites et des opérateurs distincts reste
indispensable : Onionbalance ne protège pas contre un nœud qui journalise ou
qui ment, seulement contre une panne. La validation DNSSEC côté client
(mission 12) limite le mensonge sur les zones signées.

## PoW derrière Onionbalance

La preuve de travail de Tor (`HiddenServicePoWDefensesEnabled 1`, mission 7)
est portée par le descripteur du service. Onionbalance 0.2.4 construit son
descripteur avec `stem 1.8.2`, qui ne connaît pas les paramètres PoW : il ne
peut donc pas les recopier.

Mesuré par `scripts/verifier-m09.sh` sur le descripteur réel :

- les instances déclarent bien `pow-params` (présent sur les trois
  instances) ;
- le descripteur maître n'en contient aucun (absent).

Conséquence : **la PoW est perdue derrière l'adresse maîtresse**. Un client qui
passe par Onionbalance ne peut pas être protégé par la PoW du nœud. Pistes, à
trancher :

1. patcher onionbalance pour recopier `pow-params` dans le descripteur maître
   (le format est dans la proposition 327) et suivre la version de Tor ;
2. implémenter une PoW applicative au niveau HTTP/DoH, avec un client qui la
   calcule — plus de travail des deux côtés ;
3. à défaut, conserver les limites par circuit (mission 7) et la validation
   DNSSEC côté client, qui ne protègent pas d'une saturation mais limitent les
   réponses falsifiées.

En attendant, ne pas présenter l'adresse maîtresse comme protégée par la PoW.

## Ce qui n'est pas prouvé ici

- Un déploiement sur plusieurs VPS distincts : les trois nœuds de la preuve
  tournent sur un seul hôte de test, sur le vrai réseau Tor.
- La survie complète du descripteur jusqu'à expiration : la continuité a été
  mesurée quelques minutes, la durée déclarée est lue dans le descripteur.
- La tenue au-delà de trois instances et la limite réelle des 10 instances.
- Une restauration de sauvegarde chiffrée réellement exécutée.
