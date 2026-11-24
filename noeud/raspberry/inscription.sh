#!/bin/sh
# TorDNS — inscription au registre communauté d'une carte nœud (Mission 24).
#
# Lit /etc/tordns/tordns.txt (copie de la partition de démarrage) :
#
#   registre=<adresse .onion du registre>
#   contact=<adresse de contact, facultative, jamais publiée>
#
# Attend que Tor ait publié l'adresse d'instance, puis envoie l'inscription en
# passant par le SOCKS de Tor, comme la mission 10. Aucun secret, aucun nom de
# requête DNS, aucun identifiant de client n'est transmis.
set -eu

CONFIG=/etc/tordns/tordns.txt
DONNEES=/var/lib/tordns
ATTENTE=${TORDNS_ATTENTE_INSCRIPTION:-1800}
SERVICE=tordns-inscription

journal() { printf '%s : %s\n' "$SERVICE" "$*"; }
avertir() { printf '%s : AVERTISSEMENT : %s\n' "$SERVICE" "$*" >&2; }

[ -f "$CONFIG" ] || { journal "aucune demande d'inscription"; exit 0; }

registre=$(sed -n 's/^registre=//p' "$CONFIG" | head -n 1 | tr -d '\r ')
contact=$(sed -n 's/^contact=//p' "$CONFIG" | head -n 1 | tr -d '\r ')

case $registre in
"") avertir "registre= absent de $CONFIG : inscription ignorée"; exit 0 ;;
*.onion) ;;
*) avertir "registre= n'est pas une adresse .onion : inscription ignorée"; exit 0 ;;
esac

# Les frais de contact restent locaux : jamais envoyés au registre.
printf 'registre=%s\n' "$registre" >/etc/tordns/inscription.env

journal "attente de l'adresse d'instance"
debut=$(date +%s)
adresse=
while [ -z "$adresse" ]; do
	if [ -s "$DONNEES/tor/hs/hostname" ]; then
		adresse=$(tr -d '\r\n ' <"$DONNEES/tor/hs/hostname")
		break
	fi
	maintenant=$(date +%s)
	if [ $((maintenant - debut)) -gt "$ATTENTE" ]; then
		avertir "adresse .onion toujours absente après ${ATTENTE}s : inscription abandonnée"
		exit 0
	fi
	sleep 20
done
journal "adresse : $adresse"

# Le défi est écrit dans le dossier monté en lecture seule par le conteneur
# d'état, qui le sert sur /.well-known/tordns/defi (mission 10).
defi=$DONNEES/tor/defi
if ! /usr/local/bin/tordns-inscription \
	-registre "$registre" -adresse "$adresse" -contact "$contact" \
	-defi "$defi" -socks 127.0.0.1:19050 >/tmp/inscription.log 2>&1; then
	avertir "inscription refusée : voir /tmp/inscription.log"
	exit 0
fi
journal "inscription : $(tail -n 2 /tmp/inscription.log | tr '\n' ' ')"
if [ -s /tmp/inscription.log ]; then
	# Rien d'autre n'est conservé : ni adresse de contact, ni jeton.
	rm -f /tmp/inscription.log
fi
systemctl disable tordns-inscription.service 2>/dev/null || true
