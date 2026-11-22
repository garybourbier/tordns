# TorDNS — page d'état du nœud (Mission 8).
# Binaire statique, aucun shell dans l'image finale, utilisateur non privilégié.
FROM golang:1.22-alpine AS build

WORKDIR /src
COPY go.mod ./
COPY main.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /etat .

FROM alpine:3.22

RUN adduser -D -H -u 10000 etat
COPY --from=build /etat /usr/local/bin/etat
USER etat

EXPOSE 8081

ENTRYPOINT ["/usr/local/bin/etat"]
