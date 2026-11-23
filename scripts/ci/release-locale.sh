#!/usr/bin/env bash
# TorDNS — fabrique une arborescence de release locale pour les tests.
#   scripts/ci/release-locale.sh v0.0.0-test [dossier]
# La liste des noms vient de site/telechargements.json (source unique avec le
# site et release-assembler.sh). Ne contacte aucun serveur et ne signe rien.
set -euo pipefail

TAG=${1:-v0.0.0-test}
VERSION=${TAG#v}
RACINE=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
DEST=${2:-"$RACINE/dist/release/$TAG"}

printf '%s' "$TAG" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$' ||
	{ echo "ERREUR : tag invalide : $TAG" >&2; exit 1; }

rm -rf "$DEST"
mkdir -p "$DEST"

python3 - "$RACINE" "$DEST" "$VERSION" <<'PY'
import hashlib
import json
import pathlib
import sys

racine = pathlib.Path(sys.argv[1])
dest = pathlib.Path(sys.argv[2])
version = sys.argv[3]
liste = json.loads((racine / "site" / "telechargements.json").read_text())
for entree in liste["fichiers"]:
    nom = entree["nom"].replace("{version}", version)
    (dest / nom).write_text(f"artefact de test {nom}\n")
digest = hashlib.sha256(("test-" + version).encode()).hexdigest()
with (dest / "images.txt").open("w") as f:
    for image in ("unbound", "passerelle", "etat", "noeud-tor", "tor-client"):
        f.write(f"{image}=ghcr.io/garybourbier/tordns-{image}@sha256:{digest}\n")
PY

(
	cd "$DEST"
	find . -maxdepth 1 -type f ! -name 'SHA256SUMS*' -printf '%f\n' | sort |
		while IFS= read -r f; do sha256sum "$f"; done >SHA256SUMS.tmp
	mv SHA256SUMS.tmp SHA256SUMS
)

echo "OK : release locale $TAG dans $DEST"
ls -l "$DEST"
echo "code=0"
