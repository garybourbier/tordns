#!/usr/bin/env bash
# TorDNS — refuse un tag de release qui ne correspond pas à noeud/VERSION.
#   scripts/ci/verifier-version-tag.sh v0.8.0
set -euo pipefail

RACINE=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
TAG=${1:-}
[ -n "$TAG" ] || { echo "ERREUR : tag obligatoire" >&2; exit 1; }
printf '%s' "$TAG" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$' ||
	{ echo "ERREUR : tag de release attendu vX.Y.Z : $TAG" >&2; exit 1; }

VERSION=$(tr -d '[:space:]' <"$RACINE/noeud/VERSION")
[ "$TAG" = "v$VERSION" ] ||
	{ echo "ERREUR : tag $TAG != noeud/VERSION v$VERSION" >&2; exit 1; }
echo "OK : tag $TAG correspond à noeud/VERSION"
echo "code=0"
