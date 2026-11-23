#!/usr/bin/env bash
# TorDNS — pousse les images du nœud en multi-arch et note leurs empreintes.
#   scripts/ci/images-release.sh v0.8.0
# Exige un `docker login ghcr.io` préalable (fait par le workflow avec
# GITHUB_TOKEN, jamais avec un secret de signature). Ne pas lancer en local :
# ce script publie réellement sur GHCR.
set -euo pipefail

RACINE=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
TAG=${1:-}
[ -n "$TAG" ] || { echo "ERREUR : tag obligatoire" >&2; exit 1; }
VERSION=${TAG#v}
REGISTRE=${REGISTRE:-ghcr.io/garybourbier}
DIST=${DIST:-"$RACINE/dist"}
mkdir -p "$DIST"
: >"$DIST/images.txt"

for dockerfile in $(find "$RACINE/noeud" "$RACINE/serveur" "$RACINE/controleur" -name Dockerfile | sort); do
	contexte=$(dirname "$dockerfile")
	rel=${contexte#"$RACINE"/}
	slug=$(printf '%s' "$rel" | tr '/' '-')
	ref="$REGISTRE/tordns-$slug"
	echo "-- $rel -> $ref:$VERSION"
	docker buildx build --platform linux/amd64,linux/arm64 --push \
		-t "$ref:$VERSION" -t "$ref:latest" "$contexte"
	digest=$(docker buildx imagetools inspect "$ref:$VERSION" --format '{{.Manifest.Digest}}')
	printf '%s' "$digest" | grep -Eq '^sha256:[0-9a-f]{64}$' ||
		{ echo "ERREUR : empreinte inattendue pour $ref : $digest" >&2; exit 1; }
	printf '%s=%s@%s\n' "$slug" "$ref" "$digest" >>"$DIST/images.txt"
done

cat "$DIST/images.txt"
echo "code=0"
