# Contrôleur Onionbalance

Une adresse `.onion` **maîtresse** qui répartit les requêtes DoH sur plusieurs
nœuds (les instances) et continue de répondre quand l'un tombe. Le contrôleur
tourne sur un hôte **qui n'est pas un nœud** : il détient la clé maîtresse.

```sh
sudo ./controleur/scripts/creer-maitresse.sh
cp controleur/pools/coeur.txt.example controleur/pools/coeur.txt
$EDITOR controleur/pools/coeur.txt          # une adresse d'instance par ligne
sudo ./controleur/scripts/demarrer.sh
```

Sur chaque nœud, une seule commande le fait rejoindre le pool :

```sh
sudo ./noeud/installer.sh --maitresse <adresse-maîtresse>.onion
tordns-adresse      # adresse d'instance à mettre dans le pool
```

Le pool (`pools/coeur.txt`) et les clés (`/var/lib/tordns-controleur`,
`0700`) ne sont jamais versionnés. Schéma, ajout/retrait, pertes et rotation :
[`docs/redondance.md`](../docs/redondance.md).

Aucun port n'est publié : le contrôleur n'est joignable que par le service
caché maître. Le descripteur est publié en v3 par `onionbalance==0.2.4`
(version épinglée dans `onionbalance/Dockerfile`).
