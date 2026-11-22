# TorDNS — image Tor du nœud installable (Mission 8).
# Le `torrc` n'est pas embarqué : l'installeur le génère dans le dossier de
# données (identité, maîtresse Onionbalance) et le monte en lecture seule.
FROM alpine:3.22

RUN apk add --no-cache tor \
	&& mkdir -p /var/lib/tor \
	&& chown -R tor:tor /var/lib/tor

USER tor

ENTRYPOINT ["tor", "-f", "/etc/tor/torrc"]
