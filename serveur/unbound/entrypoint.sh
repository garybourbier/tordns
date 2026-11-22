#!/bin/sh
# Initialise (ou met à jour) l'ancre de confiance DNSSEC puis lance Unbound au
# premier plan. Unbound tourne en root uniquement pour pouvoir changer
# d'utilisateur (username: unbound) et lire l'ancre.
set -eu

mkdir -p /var/lib/unbound
chown unbound:unbound /var/lib/unbound

# La clé racine est intégrée au binaire : pas besoin de réseau au démarrage.
unbound-anchor -a /var/lib/unbound/root.key || true
chown unbound:unbound /var/lib/unbound/root.key

exec unbound -d -c /etc/unbound/unbound.conf
