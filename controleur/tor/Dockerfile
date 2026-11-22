# TorDNS — Tor du contrôleur Onionbalance (Mission 9).
# Ce Tor ne sert aucun service : il fournit à onionbalance le port de contrôle
# qui lui permet de lire les descripteurs des instances et de publier le
# descripteur maître. Aucun port n'est publié sur l'hôte.
FROM alpine:3.22

RUN apk add --no-cache tor \
	&& mkdir -p /var/lib/tor \
	&& chown -R tor:tor /var/lib/tor

COPY torrc /etc/tor/torrc
RUN chmod 0644 /etc/tor/torrc

USER tor

ENTRYPOINT ["tor", "-f", "/etc/tor/torrc"]
