# TorDNS — registre communautaire (Mission 10).
FROM golang:1.23-alpine@sha256:383395b794dffa5b53012a212365d40c8e37109a626ca30d6151c8348d380b5f AS construction
WORKDIR /src
COPY go.mod ./
COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /registre .

FROM alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f
RUN adduser -D -u 10001 registre \
	&& mkdir -p /donnees /pools \
	&& chown registre:registre /donnees /pools
COPY --from=construction /registre /usr/local/bin/registre
USER registre
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/registre"]
