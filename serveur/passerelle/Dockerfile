FROM golang:1.22-alpine AS build

WORKDIR /src
COPY go.mod ./
COPY main.go ./
# Aucune dépendance externe : construction hors ligne, binaire statique.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /passerelle .

FROM alpine:3.22

RUN adduser -D -H -u 10001 passerelle
COPY --from=build /passerelle /usr/local/bin/passerelle
USER passerelle

EXPOSE 8053

ENTRYPOINT ["/usr/local/bin/passerelle"]
