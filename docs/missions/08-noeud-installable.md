# Mission 8 — Un nœud installable en une commande

But : Gary (3 petits VPS) ou un bénévole monte un nœud TorDNS complet sur un Debian 12/13
vierge avec une seule commande, sans rien savoir de Docker ni de Tor.

## À livrer

- `noeud/installer.sh` (POSIX sh, idempotent, relançable) :
  - vérifie l'OS, la RAM (≥ 1 Go conseillé), installe Docker depuis les paquets Debian ;
  - crée un utilisateur système `tordns`, le dossier `/opt/tordns` (code) et
    `/var/lib/tordns` (clés, état — 0700) ;
  - génère l'**identité du nœud** au premier lancement : la clé du service caché d'instance
    (par Tor lui-même) ; rien n'est jamais envoyé ailleurs ;
  - pose une unité systemd `tordns.service` qui lance la stack ;
  - option `--maitresse <adresse>` qui écrit `ob_config` et active
    `HiddenServiceOnionbalanceInstance 1` (préparation de la mission 9) ;
  - affiche à la fin l'adresse `.onion` d'instance et la commande pour la retrouver.
- `noeud/desinstaller.sh` qui retire tout SAUF les clés, et le dit (les clés se suppriment
  à part, après confirmation tapée).
- Page d'état publique servie par le nœud sur `/.well-known/tordns/etat` (JSON) : version du
  logiciel, état d'Unbound et de Tor, charge grossière (faible / moyenne / forte). **Aucun**
  compteur de requêtes par domaine ni par client.
- Ressources bornées dans `docker-compose.yml` (mémoire, CPU) pour tenir sur un VPS à 1 Go.

## Preuve (`scripts/verifier-m08.sh`)

Dans un conteneur ou une VM Debian jetable (pas sur la machine de Gary) : installation à
blanc, relance (idempotence), requête DoH par le `.onion` d'instance, page d'état lisible,
désinstallation qui garde les clés.

## Hors sujet

Onionbalance (mission 9), mises à jour (mission 11).
