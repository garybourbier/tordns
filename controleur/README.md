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

## Pool communauté et registre (Mission 10)

Les bénévoles ne passent jamais par `pools/coeur.txt`. Le registre les admet
dans `pools/communaute.txt`, qui alimente un **second** Onionbalance avec sa
propre clé. Deux identités, jamais confondues :

```sh
sudo ./controleur/scripts/creer-maitresse.sh                     # cœur
sudo ./controleur/scripts/creer-maitresse.sh --nom communaute    # communauté
sudo ./controleur/scripts/demarrer.sh
```

Le registre écoute sur le réseau privé du contrôleur et n'est publié que par
le service caché `registre` (clé générée par Tor dans `$DONNEES/tor/registre`,
adresse affichée par `sudo cat $DONNEES/tor/registre/hostname`). Il expose :

- `POST /inscription` `{adresse_instance, contact_facultatif}` : crée un défi ;
- `POST /inscription/confirmer` `{adresse_instance}` : vérifie que le nœud sert
  le défi sur `/.well-known/tordns/defi` ;
- `GET /` page publique (adresse, ancienneté, disponibilité, sans contact) ;
- `GET /etat` même contenu en JSON.

Un candidat n'est admis qu'après **72 h de sondes toutes réussies** (réglable
par `-quarantaine`). À chaque passe, trois domaines sont tirés au hasard dans
la liste publique (`domaines.txt`) et les réponses A, le RCODE et le bit AD du
nœud sont comparés à la résolution DNSSEC d'Unbound. Une intersection d'au
moins une adresse suffit : un CDN ou un tourniquet peut légitimement renvoyer
un autre ensemble. Un RCODE ou un AD différent, ou un ensemble disjoint sur
une réponse signée, est un mensonge immédiat. Sur une réponse non signée, un
ensemble disjoint n'est qu'un doute : il en faut plusieurs sur des domaines
distincts (`-doutes-max`, 3 par défaut) pour disqualifier. Un mensonge évince
immédiatement ; une indisponibilité prolongée aussi. Le registre limite les
inscriptions par circuit Tor (PROXY v2) et par jour ; derrière Tor, une limite
par adresse réseau seule n'aurait aucun sens.

Le pool communauté est appliqué par un timer de deux minutes :

```sh
sudo install -m 0644 controleur/systemd/tordns-recharger-communaute.* /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now tordns-recharger-communaute.timer
```

`recharger-communaute.sh` ne redémarre le second Onionbalance que si la
configuration a changé. Un pool vide conserve la dernière configuration
valide (on ne coupe pas l'adresse communauté parce qu'un dernier nœud part).

**Ce qui n'est pas prouvable** : qu'un bénévole ne journalise pas. La page
publique et les clients doivent le dire ; la validation DNSSEC côté client
(mission 12) limite le mensonge sur les zones signées, pas la collecte.
