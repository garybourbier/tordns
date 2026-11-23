FROM golang:1.22-alpine@sha256:1699c10032ca2582ec89a24a1312d986a3f094aed3d5c1147b19880afe40e052 AS build

WORKDIR /src
COPY go.mod ./
COPY main.go ./
# Aucune dépendance externe : construction hors ligne, binaire statique.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /passerelle .

FROM alpine:3.22@sha256:49340b346798875b5592e5d420241f2f9cfba5f47e62ebb1446a1b34734e898f

RUN adduser -D -H -u 10001 passerelle
COPY --from=build /passerelle /usr/local/bin/passerelle
USER passerelle

EXPOSE 8053

ENTRYPOINT ["/usr/local/bin/passerelle"]
