FROM alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f

RUN apk add --no-cache tor curl \
	&& mkdir -p /var/lib/tor-client \
	&& chown -R tor:tor /var/lib/tor-client

COPY torrc /etc/tor/torrc
RUN chmod 0644 /etc/tor/torrc

USER tor

ENTRYPOINT ["tor", "-f", "/etc/tor/torrc"]
