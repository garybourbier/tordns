FROM alpine:3.22

RUN apk add --no-cache tor curl \
	&& mkdir -p /var/lib/tor-client \
	&& chown -R tor:tor /var/lib/tor-client

COPY torrc /etc/tor/torrc
RUN chmod 0644 /etc/tor/torrc

USER tor

ENTRYPOINT ["tor", "-f", "/etc/tor/torrc"]
