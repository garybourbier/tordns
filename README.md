# TorDNS

[![CI](https://github.com/garybourbier/tordns/actions/workflows/ci.yml/badge.svg)](https://github.com/garybourbier/tordns/actions/workflows/ci.yml)
[![Dernière release](https://img.shields.io/github/v/release/garybourbier/tordns?label=release)](https://github.com/garybourbier/tordns/releases/latest)
[![Licence MIT](https://img.shields.io/badge/licence-MIT-blue)](LICENSE)

TorDNS est un relais DNS qui envoie les requêtes par Tor vers un réseau de
nœuds bénévoles, avec cache borné, validation DNSSEC côté client et mises à
jour signées. Il vise les réseaux qui censurent ou détournent le DNS, les
résolveurs menteurs et la fuite des noms de domaine vers le fournisseur
d’accès.

## Télécharger

La page de présentation est sur **<https://garybourbier.github.io/tordns/>**.
Les liens ci-dessous pointent vers la dernière release GitHub ; les mêmes noms
sont produits par `release.yml` et affichés par le site.

| Plateforme | Architecture | Fichier |
|---|---|---|
| Windows | x86_64 | [installateur](https://github.com/garybourbier/tordns/releases/latest/download/tordns-client-0.8.0-windows-x86_64-setup.exe) |
| Windows | aarch64 | [installateur](https://github.com/garybourbier/tordns/releases/latest/download/tordns-client-0.8.0-windows-aarch64-setup.exe) |
| macOS | Intel et Apple Silicon | [paquet .pkg](https://github.com/garybourbier/tordns/releases/latest/download/tordns-client-0.8.0-macos-universel.pkg) · [binaire](https://github.com/garybourbier/tordns/releases/latest/download/tordns-client-0.8.0-macos-universel) |
| Linux | amd64 | [archive](https://github.com/garybourbier/tordns/releases/latest/download/tordns-client-0.8.0-linux-amd64.tar.gz) · [.deb](https://github.com/garybourbier/tordns/releases/latest/download/tordns-client-0.8.0-linux-amd64.deb) |
| Linux | arm64 | [archive](https://github.com/garybourbier/tordns/releases/latest/download/tordns-client-0.8.0-linux-arm64.tar.gz) · [.deb](https://github.com/garybourbier/tordns/releases/latest/download/tordns-client-0.8.0-linux-arm64.deb) |
| Linux | armv7 | [archive](https://github.com/garybourbier/tordns/releases/latest/download/tordns-client-0.8.0-linux-armv7.tar.gz) |
| OpenWrt | ramips/mt7621 | [paquet apk](https://github.com/garybourbier/tordns/releases/latest/download/tordns-0.8.0-r1-openwrt-mipsel_24kc.apk) |
| OpenWrt | mediatek/filogic | [paquet apk](https://github.com/garybourbier/tordns/releases/latest/download/tordns-0.8.0-r1-openwrt-aarch64_cortex-a53.apk) |
| Raspberry Pi (nœud) | arm64 | [image prête à flasher](https://github.com/garybourbier/tordns/releases/latest/download/tordns-noeud-rpi-0.8.0-arm64.img.xz) |
| Android | universel | [APK](https://github.com/garybourbier/tordns/releases/latest/download/tordns-client-0.8.0-android-universel.apk) |
| Android | arm64-v8a | [APK](https://github.com/garybourbier/tordns/releases/latest/download/tordns-client-0.8.0-android-arm64-v8a.apk) |
| Android | armeabi-v7a | [APK](https://github.com/garybourbier/tordns/releases/latest/download/tordns-client-0.8.0-android-armeabi-v7a.apk) |
| Android | x86_64 | [APK](https://github.com/garybourbier/tordns/releases/latest/download/tordns-client-0.8.0-android-x86_64.apk) |

Vérification : `SHA256SUMS` et les attestations de provenance sont joints à la
release. La procédure complète est décrite dans
[Publier une version](docs/publier-une-version.md).

```bash
gh attestation verify <fichier> --repo garybourbier/tordns
sha256sum -c SHA256SUMS
```

## Démarrage rapide

### Linux

```bash
sudo apt install ./tordns-client-0.8.0-linux-amd64.deb
sudoedit /etc/tordns/client.env    # TORDNS_ONION=<adresse .onion>
sudo systemctl enable --now tordns-client
tordns-client --diagnostic         # cherche les fuites DNS restantes
```

Détails, cache, DNSSEC et mise à jour : [client Linux](client-linux/README.md).

### Windows

1. Lancer l’installateur x86_64 ou aarch64, puis renseigner
   `C:\ProgramData\TorDNS\client.conf` (`onion = <adresse .onion>`).
2. Démarrer le service `TorDNS` (gestionnaire de services) avec un proxy Tor
   local sur `127.0.0.1:9050`.
3. Contrôler avec `tordns-client --diagnostic`.

Détails et limites : [client Windows](client-windows/README.md).

### macOS

```bash
sudo installer -pkg tordns-client-0.8.0-macos-universel.pkg -target /
sudo "$EDITOR" "/Library/Application Support/TorDNS/client.env"
sudo launchctl kickstart -k system/org.tordns.client
```

Le paquet n’est pas signé par Apple pour l’instant : clic droit → **Ouvrir**.
Détails : [client macOS](client-macos/README.md).

### Android

1. Installer l’APK correspondant à l’appareil (ou l’APK universel).
2. Ouvrir TorDNS, saisir l’adresse `.onion`, puis activer la protection et
   accepter la demande VPN d’Android.
3. Laisser « DNS privé » sur « Désactivé » pour éviter le DoT hors tunnel.

Détails : [client Android](client-android/README.md).

### OpenWrt (routeur)

Sur un routeur OpenWrt 25.12 (≥ 256 Mo de RAM), le paquet protège tout le
LAN : dnsmasq transfère vers le relais local et le pare-feu bloque le DNS
direct et le DoT des appareils.

```sh
apk add --allow-untrusted ./tordns-0.8.0-r1-openwrt-mipsel_24kc.apk
uci set tordns.main.onion='<adresse>.onion' && uci commit tordns
/etc/init.d/tordns enable && /etc/init.d/tordns start
```

Choisir le paquet correspondant au routeur (`ramips/mt7621` en mipsel,
`mediatek/filogic` en arm64). Détails, réglages UCI et anti-fuite :
[paquet OpenWrt](client-openwrt/README.md).

## Héberger un nœud

Un nœud Debian 12/13 sert un service caché Tor et ne publie aucun port sur
Internet. Il demande environ 1 Go de RAM.

```bash
git clone https://github.com/garybourbier/tordns.git && cd tordns && sudo ./noeud/installer.sh
```

Pour un Raspberry Pi 4 ou 5, l'image `tordns-noeud-rpi-0.8.0-arm64.img.xz`
contient Debian allégé et le nœud déjà installé : `xz -dc … | sudo dd of=/dev/sdX`,
puis la configuration se fait sur la carte `boot`
([détails](noeud/raspberry/README.md)).

Les images multi-arch sont publiées sur GHCR. Pour les utiliser par empreinte,
télécharger `images.txt` dans la release, le placer à côté de `noeud/`, puis
lancer `sudo ./noeud/installer.sh --images ghcr`. Sans cette option, les images
sont construites localement.

- **Cœur** : nœuds de Gary, derrière l’adresse Onionbalance maîtresse.
- **Communauté** : bénévoles admis par le registre après des sondes de justesse
  DNS ; l’adresse est distincte et les clients la choisissent explicitement.
- Pour proposer un nœud : `sudo ./noeud/installer.sh --maitresse <adresse
  communauté> --rejoindre <adresse du registre>`. Voir
  [le guide du nœud](noeud/README.md) et
  [le cadrage du réseau](docs/missions/chantier-2-cadrage.md).
- Le registre publie `/reseau` et `/reseau.json` sur son service caché :
  agrégats de sondes seulement, adresses de bénévoles tronquées. Le contrôleur
  peut aussi recevoir une copie sur GitHub Pages, désactivée par défaut (voir
  [le contrôleur](controleur/README.md)).

## Architecture

```text
clients Linux / Windows / macOS / Android
        │  DoH dans Tor, une adresse publique
        ▼
adresse CŒUR (Onionbalance)          adresse COMMUNAUTÉ (Onionbalance)
        │                                    │
        ├── nœud A ─┐                        ├── bénévole admis ─┐
        ├── nœud B ─┼─ Tor + Caddy          ├── bénévole admis ─┼─ même stack
        └── nœud C ─┘  + passerelle DoH      └── bénévole admis ─┘  + Unbound DNSSEC
                        + Unbound

contrôleur (hors des nœuds) : Onionbalance, registre .onion, sondes,
admission/éviction, manifeste signé.
```

- **Onionbalance** agrège les points d’introduction des nœuds derrière une
  adresse v3 ; chaque nœud garde son adresse d’instance et son `ob_config`.
- **Registre** : inscription en deux temps, défi vérifié, quarantaine de 72 h,
  sondes comparant RCODE, bit AD et adresses A. Un mensonge ou une
  indisponibilité prolongée évince le nœud.
- **Mises à jour** : manifeste JSON signé Ed25519 (version croissante,
  expiration, URL, taille, SHA-256, images `@sha256` et liste d’adresses). Les
  nœuds et les clients refusent une signature fausse, un rejeu ou une empreinte
  différente, et reviennent à la version précédente en cas d’échec.
- **DNSSEC** est validé côté client, pas seulement par le nœud ; le nœud reste
  une source non fiable pour les zones non signées.

## Sécurité

**Modèle de menace.** Le réseau local, le fournisseur d’accès et un Wi-Fi
public ne voient pas les noms résolus : le client parle uniquement à Tor. Le
nœud qui sert la requête voit le nom et peut le journaliser ; Tor masque
l’adresse IP du client, pas la requête à un nœud malveillant. DNSSEC protège
les zones signées contre une réponse forgée ; il ne couvre pas les zones non
signées. TorDNS ne rend pas à lui seul la navigation anonyme.

**Ce qui est prouvé localement** (détail et dates dans le
[journal des missions](docs/missions/journal.md)) : compilations Linux, Windows,
Android et macOS croisées ; tests Go/Rust/Java ; cache et TTL négatif ; 10 000
paquets hostiles par client ; signature et refus de manifeste ; retour arrière
des mises à jour ; release locale avec `SHA256SUMS` ; site sans URL hors
GitHub ; captures 360/1280 px.

**Ce qui n’est pas prouvé ici** : installation et service réels sur Windows,
lancement macOS/`launchd`/`networksetup`, session `PackageInstaller` Android,
DNSSEC contre les racines réelles, transport Tor des mises à jour, registre
avec de vrais bénévoles, publication Onionbalance sur plusieurs hôtes,
signature Developer ID/notarisation, exécution réelle des workflows GitHub et
des attestations. Aucun audit indépendant n’a été réalisé.

Pour signaler une faille, utiliser le
[signalement privé GitHub](https://github.com/garybourbier/tordns/security/advisories/new)
et lire [SECURITY.md](SECURITY.md).

## Développer

```bash
./scripts/ci/lint.sh                 # actionlint, shellcheck, gofmt/go vet, cargo fmt
./scripts/ci/client-linux.sh amd64   # un client et son archive/.deb
./scripts/ci/client-windows.sh x86_64
./scripts/ci/client-android.sh
./scripts/ci/client-macos.sh
./scripts/verifier-m18.sh            # preuves de cette mission
```

Chaque mission possède son `scripts/verifier-mNN.sh` ; les sorties sont
conservées dans les commits. Les dossiers principaux :

| Dossier | Contenu |
|---|---|
| `client-linux/` | relais Go partagé Linux/macOS, client Linux, mises à jour |
| `client-windows/` | service Rust, WinTun, installateur NSIS |
| `client-android/` | application Java, Arti Rust, APK sans Gradle |
| `client-macos/` | façade macOS, DNS système, launchd, `.pkg` |
| `noeud/` | stack Docker, installeur, page d’état, mises à jour |
| `controleur/` | Onionbalance, registre, sondes, pools |
| `outils/` | manifeste signé, publication, inscription, signature APK |
| `scripts/ci/` | compilations et lint utilisés par la CI et les preuves |
| `site/` | pages statiques françaises et anglaises |

## Historique

1. **Mission 1** — stack serveur conteneurisée (Unbound, passerelle DoH, Caddy).
2. **Mission 2** — exposition en service caché Tor v3.
3. **Mission 3** — durcissement, anti-amplification, page d’état.
4. **Mission 4** — client Linux avec cache et diagnostic de fuites.
5. **Mission 5** — client Android `VpnService` avec Arti embarqué.
6. **Mission 6** — client Windows WinTun et installateur NSIS.
7. **Mission 7** — limites par circuit, PoW, SOCKS fermé, README corrigé.
8. **Mission 8** — nœud installable en une commande, identité et état.
9. **Mission 9** — redondance Onionbalance sur trois nœuds.
10. **Mission 10** — registre et admission des bénévoles.
11. **Mission 11** — manifeste signé, mises à jour nœud et Linux.
12. **Mission 12** — mises à jour Windows/Android, adresses signées, DNSSEC.
13. **Mission 13** — cache TTL, fuites DNS, paquets hostiles.
14. **Mission 14** — CI de toutes les plateformes, paquets et images.
15. **Mission 15** — client macOS, launchd, `.pkg`.
16. **Mission 16** — releases brouillon, images GHCR, attestations.
17. **Mission 17** — site GitHub Pages bilingue.
18. **Mission 18** — ce README.
19. **Mission 19** — restes de la relecture du 23/11.

Détail, preuves et limites : [journal des missions](docs/missions/journal.md).

## Licence

MIT — voir [LICENSE](LICENSE).
