#!/usr/bin/env bash
# TorDNS — reconstruit un tag dans un conteneur propre et compare les sommes.
#   scripts/ci/reproduire.sh v0.8.0
#   scripts/ci/reproduire.sh v0.8.0 --sommes /chemin/SHA256SUMS
# Le conteneur ne contient que le code du tag et la chaîne Go épinglée ; il
# n'a ni clé, ni cache de build, ni dépôt git. La comparaison porte sur les
# fichiers Linux amd64 reconstruits. Windows, Android et macOS demandent leurs
# chaînes dédiées (CI) et ne sont pas reconstruits par ce script.
set -euo pipefail

RACINE=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
TAG=${1:-}
[ -n "$TAG" ] || { echo "ERREUR : tag obligatoire (vX.Y.Z)" >&2; exit 1; }
shift || true
SOMMES=
while [ $# -gt 0 ]; do
	case $1 in
	--sommes) [ $# -ge 2 ] || { echo "ERREUR : --sommes exige un fichier" >&2; exit 1; }; SOMMES=$2; shift 2 ;;
	*) echo "ERREUR : option inconnue : $1" >&2; exit 1 ;;
	esac
done

VERSION=${TAG#v}
SOURCE_DATE_EPOCH=$(git -C "$RACINE" log -1 --format=%ct "$TAG" 2>/dev/null) ||
	{ echo "ERREUR : tag $TAG introuvable dans le dépôt" >&2; exit 1; }
TMP=$(mktemp -d "${TMPDIR:-/tmp}/tordns-reproduire.XXXXXX")
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$RACINE/dist/reproduction/$TAG"

git -C "$RACINE" archive --format=tar "$TAG" | tar -x -C "$TMP"

echo "== Reconstruction Linux amd64 du tag $TAG (SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH)"
docker run --rm \
	-v "$TMP:/src:ro" \
	-v "$RACINE/dist/reproduction/$TAG:/sortie" \
	-e VERSION="$VERSION" -e SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
	-e DIST=/sortie -w /src \
	golang:1.23.7-bookworm@sha256:7d1571fea7cdc08fe7f37d4eacf06dfe5756366acb7bdd33cf26a7c422fed993 \
	./scripts/ci/client-linux.sh amd64

echo "== Sommes reconstruites"
(cd "$RACINE/dist/reproduction/$TAG" && sha256sum tordns-client_*)

if [ -n "$SOMMES" ]; then
	[ -r "$SOMMES" ] || { echo "ERREUR : SHA256SUMS illisible : $SOMMES" >&2; exit 1; }
	ok=0
	for fichier in "$RACINE"/dist/reproduction/"$TAG"/tordns-client_*; do
		somme=$(sha256sum "$fichier" | awk '{print $1}')
		if grep -q "^$somme  " "$SOMMES"; then
			ok=$((ok + 1))
		else
			echo "ÉCART : $(basename "$fichier") ($somme) absent de $SOMMES" >&2
		fi
	done
	[ "$ok" -gt 0 ] || { echo "ERREUR : aucune somme reconstruite ne correspond" >&2; exit 1; }
	echo "OK : $ok fichier(s) reconstruit(s) identique(s) au SHA256SUMS"
fi
echo "code=0"
