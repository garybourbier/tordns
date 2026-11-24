# TorDNS — nœud prêt pour Raspberry Pi (Mission 24)

Une carte SD à flasher, un Raspberry Pi à brancher : le bénévole devient un
nœud communauté sans connaître Docker. Le nœud ne publie aucun port sur
Internet ; son unique entrée est son service caché Tor.

## Matériel

| Matériel | Verdict | Notes |
| --- | --- | --- |
| Raspberry Pi 4, 2 Go | recommandé | 1 Go suffit au nœud, 2 Go laissent de la marge pour Docker |
| Raspberry Pi 5 | recommandé | plus rapide, consommation plus élevée au repos |
| Raspberry Pi 3 B / B+ | possible | mémoire juste, à mesurer avant de le conseiller |
| Carte SD 8 Go classe A1/A2 | minimum | l'image fait 4 Gio, étendue à la carte au premier démarrage |
| SSD USB 3 | conseillé | la carte SD s'use ; un SSD évite les corruptions |
| Alimentation officielle | obligatoire | une alimentation faible provoque des corruptions |

Consommation observée d'un Pi 4 avec cette pile : de l'ordre de 3 à 5 W au
repos, à mesurer sur le matériel réel. **NON PROUVÉ** : aucune mesure n'a été
faite sur un vrai Pi.

Aucun écran ni clavier n'est nécessaire. SSH est **désactivé** par défaut et
aucun compte n'a de mot de passe : la carte ne s'administre pas à distance.

## Construire l'image

```bash
./scripts/ci/image-rpi.sh
```

Le script télécharge Raspberry Pi OS Lite 64 bits officiel et les binaires
statiques de Docker (deux SHA-256 épinglés), puis modifie l'image **sans
privilèges** : les partitions sont extraites dans des fichiers, éditées avec
`mtools` et `debugfs` dans un conteneur non privilégié, puis réinsérées. Aucun
montage en boucle, aucun `systemd-nspawn`, aucun `root` sur la machine qui
construit.

Sortie : `dist/rpi/tordns-noeud-rpi-<version>-arm64.img.xz` et son `.sha256`
(591 Mo compressés, moins de 2 Go comme demandé).

## Flasher et brancher

1. Écrire l'image sur la carte, par exemple avec Raspberry Pi Imager ou :

   ```bash
   xz -dc tordns-noeud-rpi-0.8.0-arm64.img.xz | sudo dd of=/dev/sdX bs=4M conv=fsync status=progress
   ```

   Ne pas utiliser l'assistant d'Imager pour créer un compte ou activer SSH :
   l'image n'en veut pas.

2. Facultatif : monter la partition de démarrage (la seule visible depuis un
   ordinateur) et y déposer `tordns.txt`, sur le modèle de
   `tordns.txt.exemple` :

   ```ini
   registre=exempleexempleexempleexempleexempleexempleexempleexemple.onion
   contact=
   ```

   Sans ce fichier, la carte devient un nœud autonome et ne demande aucune
   inscription.

3. Brancher le câble réseau (le Wi-Fi n'est pas configuré), puis l'alimentation.

## Premier démarrage

`tordns-premier-demarrage.service` s'exécute une seule fois :

1. crée l'utilisateur système `tordns` ;
2. étend la partition racine à la taille de la carte ;
3. **génère les clés du service caché sur la carte** (`/var/lib/tordns/tor/hs`,
   `0700`, propriétaire `tordns`) — jamais dans l'image, jamais deux fois les
   mêmes ;
4. charge le pare-feu : tout est fermé, sauf la page d'état depuis les plages
   privées ;
5. installe le nœud avec l'installeur commun en mode images GHCR épinglées par
   empreinte, **si** `noeud/images.txt` est présent (il vient de la release) ;
6. active `tordns-inscription.service` si `tordns.txt` demande l'inscription :
   le service attend l'adresse d'instance, puis envoie la demande par Tor.

L'image contient Docker en binaires statiques, le code du nœud dans
`/opt/tordns`, les outils ci-dessus et la page d'état. Elle ne contient ni clé,
ni mot de passe, ni accès SSH.

## Page d'état locale

```
http://tordns.local          page lisible par un humain
http://tordns.local/etat     même état en JSON
```

`avahi-daemon` publie le nom `tordns.local` sur le LAN. La page affiche : nœud
en ligne, adresse d'instance, inscription en quarantaine ou admise, état des
mises à jour, premier démarrage terminé. Elle ne lit que des fichiers locaux et
l'état du service : **aucune requête DNS, aucun nom de domaine, aucun
identifiant de client, aucun journal**.

La même page n'est pas exposée sur Internet : le pare-feu n'ouvre le port 80
que depuis `10/8`, `172.16/12` et `192.168/16`.

## Codes et fichiers utiles

| Chemin | Contenu |
| --- | --- |
| `/opt/tordns` | code du nœud, installeur, `noeud/images.txt` si l'image vient d'une release |
| `/var/lib/tordns` | clés, état, marqueur de premier démarrage (`0700`) |
| `/etc/tordns/pare-feu.nft` | règles nftables chargées au premier démarrage |
| `/etc/tordns/tordns.txt` | copie de la demande d'inscription |
| `/usr/local/bin/tordns-cles-onion` | génération des clés v3 (format Tor) |
| `/usr/local/bin/tordns-etat-local` | page d'état |
| `/usr/local/bin/tordns-inscription` | inscription au registre |

Journaux : `journalctl -u tordns-premier-demarrage`, `-u tordns`,
`-u tordns-etat-local`, `-u tordns-inscription`.

## Ce qui n'est pas prouvé

- Aucun démarrage sur un vrai Raspberry Pi : la preuve se fait dans QEMU
  `raspi3b` avec le noyau de l'image (`scripts/verifier-m24.sh`), qui n'émule
  ni le chien de garde, ni la carte SD, ni l'alimentation.
- L'extension de la partition n'est vérifiée que sur une image de 4 Gio.
- L'installation du nœud par images GHCR n'a pas été exercée : le dépôt ne
  contient pas `noeud/images.txt` (il est produit par la release). Le premier
  démarrage le signale et continue sans installer le nœud.
- L'inscription réelle au registre communauté et l'affichage de `tordns.local`
  depuis un autre appareil du LAN n'ont pas été mesurés.
