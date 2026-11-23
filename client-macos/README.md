# Client TorDNS pour macOS

Relais DNS local vers le service caché TorDNS, équivalent du client Linux :
cache borné, DNSSEC, liste d'adresses signée, aucun journal de requêtes.

## Télécharger

Prendre `tordns-client-0.8.0-macos-universel.pkg` (ou le binaire universel)
dans la [dernière release](https://github.com/garybourbier/tordns/releases/latest)
ou sur la [page de présentation](https://garybourbier.github.io/tordns/).

## Prérequis

- macOS 12 ou ultérieur, Intel ou Apple Silicon.
- Tor installé et démarré (Homebrew : `brew install tor && brew services start tor`).
- Droits administrateur pour le port 53 et le réglage DNS système.

## Installation

Depuis un `.pkg` non signé : clic droit → **Ouvrir** (Gatekeeper refuse le
double-clic tant que Gary n'a pas signé/notarisé le paquet).

Depuis les sources, après `scripts/ci/client-macos.sh` :

```sh
sudo ./client-macos/installer.sh
sudo "$EDITOR" "/Library/Application Support/TorDNS/client.env"
```

Renseigner `TORDNS_ONION` avec l'adresse du service caché, puis :

```sh
sudo launchctl kickstart -k system/org.tordns.client
/usr/local/bin/tordns-client -diagnostic
```

Le client refuse de démarrer si le proxy SOCKS de Tor est injoignable : il ne
retombe jamais en DNS clair. Il sauvegarde les DNS de chaque service réseau
actif dans `/Library/Application Support/TorDNS/dns-original.json`
(root:wheel, 0700) avant de pointer ces services vers `127.0.0.1`.

## Mise à jour

`tordns-client-maj` lit le même manifeste signé que Linux, avec la cible
`client-macos` (binaire universel), remplace le binaire atomiquement puis
exécute `launchctl kickstart -k system/org.tordns.client`. Une version dont le
service ne redémarre pas est notée `rejetee` et n'est pas retentée.

## Désinstallation

```sh
sudo ./client-macos/desinstaller.sh
```

Le script restaure les DNS d'origine avant de retirer le service, les binaires
et l'état. `client.env` est conservé pour une réinstallation.

## Limites

- Le paquet n'est ni signé ni notarisé par la CI : Gary signe avec son
  Developer ID et notarise s'il fournit les secrets Apple.
- Le lancement réel sur Mac, `networksetup`, `scutil`, `launchd` et
  l'installation d'un `.pkg` ne sont pas prouvés sur cette machine Linux ; les
  analyseurs de fixtures et les compilations croisées le sont.
- Un arrêt forcé (SIGKILL) ne restaure pas les DNS ; l'état est conservé et
  `tordns-client -restaurer-dns` (ou le désinstalleur) les remet.
