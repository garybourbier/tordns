#!/usr/bin/env bash
# TorDNS — construit toutes les images Docker du nœud, du serveur et du
# contrôleur pour une architecture, sans pousser.
#   scripts/ci/noeud-images.sh amd64|arm64
set -euo pipefail

RACINE=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
ARCH=${1:-}
case "$ARCH" in amd64|arm64) ;; *) echo "ERREUR : architecture attendue amd64 ou arm64" >&2; exit 1 ;; esac
DIST=${DIST:-"$RACINE/dist/noeud-images"}
mkdir -p "$DIST"

section() { printf '\n== %s ==\n' "$*"; }
section "Images linux/$ARCH"

for dockerfile in $(find "$RACINE/noeud" "$RACINE/serveur" "$RACINE/controleur" -name Dockerfile | sort); do
	contexte=$(dirname "$dockerfile")
	rel=${contexte#"$RACINE"/}
	slug=$(printf '%s' "$rel" | tr '/' '-')
	tag="tordns/ci-$slug:$ARCH"
	echo "-- $rel"
	docker buildx build --platform "linux/$ARCH" --load -t "$tag" "$contexte"
	architecture=$(docker image inspect "$tag" --format '{{.Architecture}}')
	[ "$architecture" = "$ARCH" ] || {
		echo "ERREUR : $tag est en $architecture, attendu $ARCH" >&2
		exit 1
	}
	docker save "$tag" -o "$DIST/$slug-$ARCH.tar"
done

section "Résultat"
ls -lh "$DIST"
echo "code=0"
