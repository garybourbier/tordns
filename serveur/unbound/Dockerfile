FROM alpine:3.22

# unbound : le résolveur ; bind-tools fournit dig, utilisé par le healthcheck
# et par la preuve de la Mission 1.
RUN apk add --no-cache unbound bind-tools

RUN mkdir -p /var/lib/unbound && chown unbound:unbound /var/lib/unbound

COPY unbound.conf /etc/unbound/unbound.conf
COPY root.hints /etc/unbound/root.hints
COPY entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh

EXPOSE 5335/tcp 5335/udp

ENTRYPOINT ["/entrypoint.sh"]
