#!/usr/bin/env bash
# TorDNS — extrait du CHANGELOG la section d'une version.
#   scripts/ci/notes-release.sh v0.8.0
set -euo pipefail

RACINE=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
TAG=${1:-}
[ -n "$TAG" ] || { echo "ERREUR : tag obligatoire" >&2; exit 1; }
VERSION=${TAG#v}
FICHIER="$RACINE/CHANGELOG.md"
[ -f "$FICHIER" ] || { echo "ERREUR : CHANGELOG.md absent ; créez la section $VERSION." >&2; exit 1; }

mkdir -p "$RACINE/dist"
awk -v version="$VERSION" '
	/^##[[:space:]]/ {
		if (trouve) exit
		if ($0 ~ ("(^|[^0-9A-Za-z.])" version "([^0-9A-Za-z.]|$)")) trouve = 1
		next
	}
	trouve { print }
	END { if (!trouve) exit 3 }
' "$FICHIER" >"$RACINE/dist/notes-release.tmp" || {
	echo "ERREUR : section $VERSION absente de CHANGELOG.md ; créez-la avant le tag." >&2
	exit 1
}
if [ ! -s "$RACINE/dist/notes-release.tmp" ]; then
	echo "ERREUR : section $VERSION vide ou absente de CHANGELOG.md" >&2
	exit 1
fi
cat "$RACINE/dist/notes-release.tmp"
rm -f "$RACINE/dist/notes-release.tmp"
