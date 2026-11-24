# Mission 23 — Paquet OpenWrt (routeur)

But : installer TorDNS sur un routeur OpenWrt protège tout le réseau de la maison, objets
connectés compris, sans rien installer sur chaque appareil.

## À livrer

- `client-openwrt/` : paquet `tordns` au format du SDK OpenWrt (`Makefile` de paquet),
  basé sur le binaire Go du client Linux compilé statiquement pour les architectures
  courantes des routeurs : `mipsle` (softfloat), `mips` (softfloat), `arm` (v7),
  `arm64`, `amd64`. Taille du binaire mesurée et réduite (`-s -w`, et `upx` **non** : il
  gêne la vérification des sommes).
- Tor : dépendance au paquet `tor` d'OpenWrt (SOCKS local) ; documenter la RAM nécessaire
  (Tor sur 64 Mo de RAM ne tient pas : l'écrire, recommander 256 Mo).
- Intégration : service `procd` (`/etc/init.d/tordns`), configuration UCI
  (`/etc/config/tordns` : adresse, mode cœur/secours/communauté, DNSSEC, cache), dnsmasq
  réglé pour transférer vers `127.0.0.1#5353` (`noresolv`, `server=`), et **anti-fuite** :
  règle nftables (fw4) qui redirige ou bloque le port 53 sortant des clients du LAN vers
  autre chose que le routeur, et bloque DoT (853) sortant ; option pour la désactiver.
- Page LuCI minimale (`luci-app-tordns`) : état, adresse utilisée, test de fuite.
- Construction : `scripts/ci/client-openwrt.sh` avec le SDK OpenWrt de la dernière version
  stable (téléchargé, SHA-256 épinglé) pour au moins `ramips/mt7621` (mipsel) et
  `mediatek/filogic` (arm64) ; `.ipk` (et `.apk` si la version stable d'OpenWrt est passée
  au nouveau gestionnaire). Ajouté à la matrice CI et à la release.

## INTERDIT : conteneur privilégié (incident du 24/11/2026)

Le 24/11 à 01:08, `docker run --privileged openwrt/rootfs … /sbin/init` (conteneur
`tordns-openwrt-test`) a fait redémarrer le PC de Gary : en mode privilégié, `procd` voit les
périphériques de l'hôte, prend le **chien de garde matériel** (`/dev/watchdog`), coupe la session
graphique, et la machine est réinitialisée une minute après l'arrêt du conteneur.
- **Jamais `--privileged`**, jamais `--device`, jamais `/dev` monté, jamais `/sbin/init` d'OpenWrt
  lancé directement dans Docker sur cette machine.
- Le test système se fait dans **QEMU** (image `openwrt-*-x86-64-generic-ext4-combined.img`,
  `qemu-system-x86_64 -nographic -m 256 -snapshot`, réseau utilisateur `-nic user`), ou dans un
  conteneur NON privilégié qui lance seulement les binaires à tester (`dnsmasq`, `nft --check`,
  le relais) sans init.
- En cas de doute : écrire au journal « à confier à Claude » et ne pas lancer.

## Preuve (`scripts/verifier-m23.sh`)

Binaires compilés pour chaque arch (vérifier avec `file`) ; paquet construit avec le SDK ;
image OpenWrt x86_64 lancée dans QEMU (ou conteneur `openwrt/rootfs`) avec le paquet
installé : dnsmasq transfère bien au relais, une requête DNS directe vers 1.1.1.1 depuis un
client du LAN simulé est bloquée. NON PROUVÉ attendu : vrai routeur matériel.
