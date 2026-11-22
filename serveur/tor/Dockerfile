FROM alpine:3.22

RUN apk add --no-cache tor \
	&& mkdir -p /var/lib/tor \
	&& chown -R tor:tor /var/lib/tor

COPY torrc /etc/tor/torrc
RUN chmod 0644 /etc/tor/torrc

USER tor

EXPOSE 9050

ENTRYPOINT ["tor", "-f", "/etc/tor/torrc"]
