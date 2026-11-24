#!/bin/sh
# Test système de la mission 23, exécuté DANS l'image OpenWrt x86_64 sous QEMU.
# Écrit son verdict dans /tmp/resultat.log ; le pilote le lit sur le port série.
# Aucun nom de domaine résolu n'est journalisé : seules des valeurs de test
# (test.tordns, example.com) apparaissent, et on vérifie justement qu'elles ne
# se retrouvent pas dans les journaux.

LOG=/tmp/resultat.log
ECHECS=/tmp/echecs
: >"$LOG"
: >"$ECHECS"

note() { echo "$*" >>"$LOG"; }
ok() { note "OK : $*"; }
ko() { note "ÉCHEC : $*"; echo "$*" >>"$ECHECS"; }
bloc() { note ""; note "== $* =="; }

# 1. WAN (la deuxième carte QEMU reçoit un bail du réseau utilisateur).
bloc "WAN"
uci set network.wan=interface
uci set network.wan.device='eth1'
uci set network.wan.proto='dhcp'
uci commit network
/etc/init.d/network reload >/dev/null 2>&1
i=0
while [ $i -lt 30 ]; do
	ip addr show eth1 2>/dev/null | grep -q 'inet ' && break
	sleep 1
	i=$((i + 1))
done
if ip addr show eth1 2>/dev/null | grep -q 'inet '; then
	ok "interface WAN avec adresse"
else
	ko "interface WAN sans adresse"
fi
if ping -c 1 -W 3 10.0.2.2 >/dev/null 2>&1; then
	ok "passerelle QEMU joignable depuis le routeur"
else
	ko "passerelle QEMU injoignable"
fi

# 2. Paquet et binaires.
bloc "paquet"
if wget -q -O /tmp/tordns.apk http://10.0.2.2:8123/tordns-0.8.0-r1-x86_64.apk; then
	ok "paquet récupéré sur l'hôte de test"
else
	ko "paquet non récupéré"
fi
apk update >/tmp/apk.log 2>&1
if apk add --allow-untrusted /tmp/tordns.apk >>/tmp/apk.log 2>&1; then
	ok "paquet installé avec ses dépendances"
else
	ko "installation du paquet"
	tail -5 /tmp/apk.log >>"$LOG"
fi
if [ -x /usr/sbin/tordns-client ]; then
	ok "binaire /usr/sbin/tordns-client installé"
else
	ko "binaire absent"
fi
version=$(/usr/sbin/tordns-client -version 2>&1)
if [ "$version" = "tordns-client 0.8.0" ]; then
	ok "version : $version"
else
	ko "version inattendue : $version"
fi
if [ -f /etc/config/tordns ] && [ -x /etc/init.d/tordns ] && [ -f /etc/tordns/anti-fuite.nft.template ]; then
	ok "configuration, service procd et modèle nftables installés"
else
	ko "fichiers de configuration manquants"
fi
apk add ip-full kmod-veth >>/tmp/apk.log 2>&1

# 3. Client du LAN simulé (espace de noms réseau relié au routeur par veth).
bloc "client du LAN simulé"
ip netns add lan 2>/dev/null
ip link add v0 type veth peer name v1 2>/dev/null
ip link set v0 up 2>/dev/null
ip link set v1 netns lan 2>/dev/null
ip addr add 10.10.0.1/24 dev v0 2>/dev/null
ip netns exec lan ip link set lo up 2>/dev/null
ip netns exec lan ip addr add 10.10.0.100/24 dev v1 2>/dev/null
ip netns exec lan ip link set v1 up 2>/dev/null
ip netns exec lan ip route add default via 10.10.0.1 2>/dev/null
# v0 entre dans la zone LAN pour que le transfert soit autorisé, comme un
# port du commutateur ; l'anti-fuite, lui, cible l'interface configurée.
idx=$(uci show firewall | sed -n "s/^firewall\.@zone\[\([0-9]*\)\]\.name='lan'$/\1/p" | head -n 1)
if [ -n "$idx" ]; then
	uci add_list "firewall.@zone[$idx].device=v0"
	uci commit firewall
	/etc/init.d/firewall reload >/dev/null 2>&1
	sleep 2
	ok "v0 ajouté à la zone LAN (index $idx)"
else
	ko "zone LAN introuvable dans la configuration du pare-feu"
fi
if ip netns exec lan ping -c 1 -W 3 10.10.0.1 >/dev/null 2>&1; then
	ok "client du LAN joignant le routeur"
else
	ko "client du LAN ne joignant pas le routeur"
fi

# 4. Configuration TorDNS et démarrage du service.
bloc "service"
uci set tordns.main.onion='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion'
uci set tordns.main.lan_iface='v0'
uci set tordns.main.anti_fuite='1'
uci set tordns.main.dnsmasq='1'
uci commit tordns
/etc/init.d/tordns enable >/dev/null 2>&1
/etc/init.d/tordns start >/tmp/service.log 2>&1
sleep 3
if /etc/init.d/tordns running >/dev/null 2>&1 || pgrep tordns-client >/dev/null 2>&1; then
	ok "service actif"
else
	ko "service inactif"
	cat /tmp/service.log >>"$LOG"
fi
i=0
while [ $i -lt 20 ] && ! netstat -lnu 2>/dev/null | grep -q ':5353 '; do
	sleep 1
	i=$((i + 1))
done
if netstat -lnu 2>/dev/null | grep -q ':5353 '; then
	ok "le relais écoute en UDP sur 127.0.0.1:5353"
else
	ko "le relais n'écoute pas sur 5353"
fi
i=0
while [ $i -lt 30 ] &&
	! grep -qE '^server=127.0.0.1#5353$' /var/etc/dnsmasq.conf.* 2>/dev/null; do
	sleep 1
	i=$((i + 1))
done
note "uci : $(uci -q show dhcp.@dnsmasq[0] | grep -E 'server|noresolv' | tr '\n' ' ')"
note "dnsmasq : $(pgrep -a dnsmasq | cut -c1-140 | tr '\n' ' ')"
if grep -qE '^(no-resolv|server=127.0.0.1#5353)$' /var/etc/dnsmasq.conf.* 2>/dev/null; then
	ok "dnsmasq transfère vers 127.0.0.1#5353 (configuration générée)"
else
	ko "transfert absent de la configuration générée de dnsmasq"
fi
i=0
while [ $i -lt 20 ] && ! nft list chain inet fw4 tordns_anti_fuite >/dev/null 2>&1; do
	sleep 1
	i=$((i + 1))
done
if nft list chain inet fw4 tordns_anti_fuite >/dev/null 2>&1; then
	ok "chaîne nftables tordns_anti_fuite présente dans fw4"
else
	ko "chaîne nftables absente"
fi

# 5. Anti-fuite : une requête directe doit être rejetée…
bloc "anti-fuite"
direct() { ip netns exec lan nslookup -timeout=3 -retry=1 example.com 1.1.1.1 2>&1; }
if direct | grep -q '^Address'; then
	ko "DNS direct vers 1.1.1.1 non bloqué"
else
	ok "DNS direct vers 1.1.1.1 bloqué"
fi
if ip netns exec lan nc -w 3 1.1.1.1 853 </dev/null >/dev/null 2>&1; then
	ko "DoT (853) non bloqué"
else
	ok "DoT (853) bloqué"
fi
# …et le DNS du routeur reste servi aux clients du LAN.
reponse_routeur=$(ip netns exec lan nslookup -timeout=15 -retry=1 example.com 10.10.0.1 2>&1)
if echo "$reponse_routeur" | grep -q '10.10.0.1' &&
	! echo "$reponse_routeur" | grep -qi 'timed out'; then
	ok "le routeur répond (SERVFAIL attendu sans Tor)"
else
	ko "le routeur ne répond plus au client du LAN : $(echo "$reponse_routeur" | tr '\n' ' ' | cut -c1-120)"
fi
# Témoin : sans la règle, la même requête directe aboutit ; le blocage vient
# donc bien de l'anti-fuite, pas d'un réseau coupé.
uci set tordns.main.anti_fuite='0'
uci commit tordns
/etc/init.d/tordns reload >/dev/null 2>&1
sleep 3
if direct | grep -q '^Address'; then
	ok "témoin : anti-fuite désactivé, DNS direct autorisé"
else
	ko "témoin : DNS direct toujours bloqué sans l'anti-fuite (réseau du test en cause)"
fi
uci set tordns.main.anti_fuite='1'
uci commit tordns
/etc/init.d/tordns reload >/dev/null 2>&1
sleep 3
if direct | grep -q '^Address'; then
	ko "DNS direct de nouveau autorisé après réactivation"
else
	ok "DNS direct de nouveau bloqué après réactivation"
fi

# 6. Transfert de dnsmasq vers 127.0.0.1#5353 : un stub sur ce port répond
# 93.184.216.34, valeur qui ne peut venir que de là.
bloc "transfert dnsmasq → relais"
# Le relais reste configuré (dnsmasq pointe toujours vers 127.0.0.1:5353) ;
# on arrête seulement le processus pour que le stub prenne sa place.
killall tordns-client >/dev/null 2>&1
sleep 1
wget -q -O /tmp/stub-dns http://10.0.2.2:8123/stub-dns && chmod +x /tmp/stub-dns
/tmp/stub-dns -ecoute 127.0.0.1:5353 >/tmp/stub.log 2>&1 &
sleep 1
note "stub : $(cat /tmp/stub.log | tr '\n' ' ')"
if netstat -lnu 2>/dev/null | grep -q ':5353 '; then
	ok "un serveur écoute sur 127.0.0.1:5353"
else
	ko "personne n'écoute sur 5353"
fi
reponse=$(ip netns exec lan nslookup -timeout=3 -retry=1 test.tordns 10.10.0.1 2>&1)
case "$reponse" in
*93.184.216.34*)
	ok "dnsmasq transfère à 127.0.0.1#5353 (réponse 93.184.216.34 du stub)"
	;;
*)
	ko "dnsmasq ne transfère pas au relais : $(echo "$reponse" | tr '\n' ' ' | cut -c1-160)"
	;;
esac
killall stub-dns >/dev/null 2>&1
/etc/init.d/tordns restart >/dev/null 2>&1
sleep 2

# 7. Aucun nom de requête dans les journaux.
bloc "journaux"
fuite=$(logread 2>/dev/null | grep -c -e 'test\.tordns' -e 'example\.com')
if [ "${fuite:-0}" = "0" ]; then
	ok "aucun nom de domaine résolu dans logread"
else
	note "lignes fautives :"
	logread 2>/dev/null | grep -e 'test\.tordns' -e 'example\.com' |
		cut -c1-200 | sed 's/^/  /' >>"$LOG"
	ko "$fuite ligne(s) de journal contenant un nom de domaine"
fi
if [ -s /tmp/service.log ] && grep -qE 'test\.tordns|example\.com' /tmp/service.log; then
	ko "un nom de domaine apparaît dans la sortie du service"
else
	ok "aucun nom de domaine dans la sortie du service"
fi

bloc "résumé"
if [ -s "$ECHECS" ]; then
	note "échecs : $(wc -l <"$ECHECS")"
	note "code=1"
else
	note "code=0"
fi
echo "FIN-TEST"
