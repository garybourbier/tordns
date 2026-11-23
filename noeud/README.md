# TorDNS — nœud installable (Mission 8)

Un nœud TorDNS complet sur un Debian 12/13 vierge, en une commande : Unbound
récursif avec DNSSEC, passerelle DoH, Caddy et service caché Tor v3, bornés
pour tenir sur un VPS à 1 Go. Aucun port DNS, DoH ou SOCKS publié sur l'hôte ;
le seul point d'entrée est l'adresse `.onion` du nœud. Aucun journal de
requête.

## Installation

```bash
sudo apt-get update && sudo apt-get install -y git
git clone <dépôt> tordns && cd tordns
sudo ./noeud/installer.sh
```

L'installeur :

1. vérifie Debian 12/13 et la mémoire (avertit sous 1 Go) ;
2. installe Docker depuis les paquets Debian s'il est absent ;
3. crée l'utilisateur système `tordns`, `/opt/tordns` (code) et
   `/var/lib/tordns` (clés, état — `0700`) ;
4. génère `/var/lib/tordns/torrc` et laisse **Tor générer lui-même**
   l'identité du service caché dans `/var/lib/tordns/tor` — rien n'est envoyé
   ailleurs ;
5. pose et active `tordns.service` (compose au démarrage, arrêt propre) ;
6. attend la publication et affiche l'adresse `.onion` d'instance.

Relancer la même commande est sans danger : le code est remplacé
atomiquement, la stack redémarre, **les clés et l'adresse restent identiques**.

Pour retrouver l'adresse plus tard :

```bash
tordns-adresse
```

## Options

```bash
sudo ./noeud/installer.sh --maitresse <56 caractères>.onion  # préparation Onionbalance (mission 9)
sudo ./noeud/installer.sh --help
```

`--maitresse` écrit `ob_config` (`MasterOnionAddress …`) dans le dossier du
service caché et active `HiddenServiceOnionbalanceInstance 1`. Sans cette
option, le nœud publie son adresse d'instance normalement ; relancer sans
l'option retire la préparation sans toucher aux clés.

## Page d'état

```
http://<adresse>.onion/.well-known/tordns/etat
```

```json
{
  "logiciel": "TorDNS",
  "version": "0.8.0",
  "services": {"unbound": "ok", "tor": "ok"},
  "charge": "faible"
}
```

La charge est grossière (`faible` < 1, `moyenne` < 3, `forte` au-delà de la
moyenne 1 min). **Aucun** compteur de requêtes, aucun nom de domaine, aucun
identifiant de client : la page ne lit que la version, une connexion TCP vers
Unbound, `status/circuit-established` du port de contrôle Tor et
`/proc/loadavg`. Le port de contrôle n'écoute que sur le réseau docker privé,
en authentification par cookie.

## Désinstallation

```bash
sudo ./noeud/desinstaller.sh
```

Retire le service, les conteneurs, `/opt/tordns` et `tordns-adresse`.
**Les clés restent** dans `/var/lib/tordns` : une réinstallation retrouve la
même adresse. Leur suppression exige une confirmation tapée :

```bash
sudo ./noeud/desinstaller.sh --supprimer-cles   # tapez SUPPRIMER
```

Un autre nœud TorDNS du même hôte n'est pas touché (projet compose distinct
`tordns-noeud`).

## Ressources

| Service    | Mémoire | CPU  |
|------------|---------|------|
| tor        | 224 Mio | 0,50 |
| unbound    | 192 Mio | 0,50 |
| caddy      | 96 Mio  | 0,25 |
| passerelle | 96 Mio  | 0,30 |
| etat       | 32 Mio  | 0,10 |

Tous les conteneurs ont `cap_drop: ALL`, `no-new-privileges`, une racine en
lecture seule, `pids_limit` et des descripteurs bornés. Les journaux Docker
sont coupés sur les cinq services (`driver: none`).

## Fichiers

- `installer.sh` — installation idempotente (POSIX sh).
- `desinstaller.sh` — retrait complet, clés conservées par défaut.
- `docker-compose.yml` — stack du nœud, réseau privé `172.28.54.0/24`.
- `tor/` — image Tor minimale ; le `torrc` est généré par l'installeur.
- `caddy/Caddyfile` — `/dns-query`, `/healthz`, page d'état.
- `etat/` — service Go de la page d'état, sans dépendance, avec tests.
- `maj/` — `tordns-maj`, vérification et application des mises à jour signées.
- `tordns-maj.timer` — vérification toutes les 6 h, à décalage aléatoire.
- `VERSION` — version affichée par la page d'état.

## Rejoindre le pool communauté (Mission 10)

Un bénévole passe explicitement l'adresse du registre et l'adresse maîtresse
**communauté**. Son nœud écrit un défi servi sur `/.well-known/tordns/defi`,
s'inscrit par Tor, puis est sondé pendant la quarantaine avant toute admission.
Il n'entre jamais dans le pool cœur automatiquement.

```bash
sudo ./noeud/installer.sh --maitresse <adresse-communauté> \
    --rejoindre <adresse-du-registre>.onion
```

L'installeur installe `tordns-inscrire`, démarre brièvement le client Tor de
mise à jour pour joindre le registre, puis l'arrête. L'admission n'est pas
immédiate : la page publique du registre affiche les nœuds admis. Un nœud
peut journaliser ses requêtes ; l'adresse communauté est séparée du cœur pour
cette raison.

## Mises à jour signées (Mission 11)

Le nœud sert le miroir `/maj/` (dernier manifeste, signature et fichiers) et
vérifie toutes les 6 h un manifeste signé Ed25519. Une mise à jour n'est
appliquée que si la signature est valide, si la version est strictement
supérieure, si le manifeste n'est pas expiré et si chaque image est désignée
par `nom@sha256:…`. Les images sont tirées par empreinte ; une étiquette est
refusée. Après relance, la sonde `/healthz` doit répondre : sinon les images
précédentes sont réappliquées et la version n'est pas enregistrée.

```bash
sudo ./noeud/installer.sh --maitresse <adresse> --cle-maj <clé publique hex>
systemctl list-timers tordns-maj.timer
journalctl -u tordns-maj.service -n 50   # version, empreintes, erreurs seulement
```

L'installeur construit `tordns-maj` dans une image `golang:1.23-alpine` puis
l'installe dans `/usr/local/bin`. Le SOCKS du client Tor de mise à jour n'écoute
que sur `127.0.0.1:19050`. La clé privée de publication ne doit jamais être
copiée sur un nœud ; voir `outils/publier/README.md` pour publier et faire
tourner la clé.

## Limites

- Testé localement (Docker de la machine de développement) ; l'installation
  des paquets Docker et l'activation systemd réelles demandent un Debian
  vierge, non disponible ici (voir le message de commit de la mission).
- Onionbalance est préparé par `--maitresse` (mission 9) ; le nœud ne publie
  pas lui-même l'adresse maîtresse.
- La mise à jour par Tor, un vrai registre Docker et un redémarrage systemd
  réel ne sont pas prouvés localement (voir `scripts/verifier-m11.sh`).
- Le port de contrôle Tor est sans mot de passe mais en cookie, accessible
  uniquement depuis le réseau docker interne ; aucun port n'est publié.
