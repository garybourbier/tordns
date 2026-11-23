# TorDNS — registre communautaire (Mission 10).
FROM golang:1.23-alpine AS construction
WORKDIR /src
COPY go.mod ./
COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /registre .

FROM alpine:3.22
RUN adduser -D -u 10001 registre \
	&& mkdir -p /donnees /pools \
	&& chown registre:registre /donnees /pools
COPY --from=construction /registre /usr/local/bin/registre
USER registre
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/registre"]
