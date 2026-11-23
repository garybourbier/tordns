# TorDNS — page d'état du nœud (Mission 8).
# Binaire statique, aucun shell dans l'image finale, utilisateur non privilégié.
FROM golang:1.22-alpine@sha256:1699c10032ca2582ec89a24a1312d986a3f094aed3d5c1147b19880afe40e052 AS build

WORKDIR /src
COPY go.mod ./
COPY main.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /etat .

FROM alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f

RUN adduser -D -H -u 10000 etat
COPY --from=build /etat /usr/local/bin/etat
USER etat

EXPOSE 8081

ENTRYPOINT ["/usr/local/bin/etat"]
