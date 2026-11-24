# TorDNS — paquet OpenWrt (Mission 23)

Installe le relais TorDNS sur un routeur OpenWrt : les appareils du LAN
utilisent le routeur comme résolveur, dnsmasq transfère à
`127.0.0.1:5353`, et le client envoie le DoH au service caché par le SOCKS de
Tor. Aucun client n’a besoin d’un logiciel TorDNS.

**RAM** : Tor seul ne tient pas dans 64 Mo. Compter **256 Mo minimum** pour
OpenWrt + Tor + dnsmasq + le relais ; 128 Mo peuvent suffire sans LuCI mais
restent serrés. Le paquet ne peut pas rendre un routeur 64 Mo compatible.

## Installation

Le paquet stable 25.12 utilise le gestionnaire `apk` (les anciennes versions
utilisaient `opkg`). Le paquet et ses dépendances sont construits par
`scripts/ci/client-openwrt.sh` :

```sh
./scripts/ci/client-openwrt.sh
# puis sur le routeur :
apk add ./tordns-0.8.0-r1.apk
```

Il faut au minimum `tor`, `dnsmasq`, `nftables` (fw4) et de la place pour le
binaire statique. Pour LuCI, construire aussi `luci-app-tordns`.

## Configuration UCI

`/etc/config/tordns` :

```sh
config tordns 'main'
	option enabled '1'
	option onion '<adresse>.onion'
	option mode 'coeur'          # coeur, secours ou communaute
	option dnssec 'auto'         # auto, strict ou non
	option cache '4096'
	option socks '127.0.0.1:9050'
	option port '5353'
	option dnsmasq '1'
	option anti_fuite '1'
	option lan_iface 'br-lan'
```

Après modification : `/etc/init.d/tordns restart`. Le service procd démarre le
client, écrit `/etc/dnsmasq.d/tordns.conf` (`no-resolv`,
`server=127.0.0.1#5353`) et recharge dnsmasq.

## Anti-fuite nftables

Si `anti_fuite` vaut `1`, le service écrit
`/etc/nftables.d/10-tordns.nft`, inclus par fw4. Les clients du LAN ne peuvent
plus joindre un résolveur DNS autre que le routeur, ni sortir en DoT (853).
Le fragment utilise `fib daddr type local` : le DNS vers l’adresse locale du
routeur reste autorisé, celui vers Internet est rejeté. Mettre `anti_fuite` à
`0` pour désactiver, puis redémarrer le service.

Cette règle ne protège pas un client qui utilise DoH (443) vers un service
externe : aucun filtrage applicatif ne peut l’empêcher sans casser le Web.
Elle empêche les fuites DNS classiques et DoT, pas le DoH choisi par
l’utilisateur.

## LuCI

`luci-app-tordns` ajoute **Services → TorDNS** : activation, adresse, mode,
DNSSEC, cache, port, dnsmasq, anti-fuite et interface LAN. Le bouton
« Tester l’état et les fuites » lance le diagnostic local du client et affiche
la chaîne nftables.

## Limites

- Le paquet ne prouve pas qu’un routeur matériel réel démarre : la preuve
  locale construit le paquet avec le SDK et teste le service dans un rootfs
  OpenWrt x86_64.
- UPX n’est pas utilisé : il gênerait la vérification des sommes. Le binaire
  est compilé avec `-s -w` et `-trimpath`.
- Le routeur doit avoir Tor actif avec `SocksPort 127.0.0.1:9050` et assez de
  mémoire. Un routeur 64 Mo n’est pas une cible réaliste.
