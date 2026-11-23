#!/usr/bin/env bash
# TorDNS — assemble les artefacts d'une release et écrit SHA256SUMS.
#   VERSION=0.8.0 scripts/ci/release-assembler.sh v0.8.0 [dist/release/v0.8.0]
# La liste des fichiers vient de site/telechargements.json : le site et la
# release partagent la même source de noms.
set -euo pipefail

RACINE=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
TAG=${1:-}
VERSION=${VERSION:-${TAG#v}}
DEST=${2:-"$RACINE/dist/release/$TAG"}
[ -n "$TAG" ] || { echo "ERREUR : tag obligatoire" >&2; exit 1; }
[ -n "$VERSION" ] || { echo "ERREUR : version obligatoire" >&2; exit 1; }

rm -rf "$DEST"
mkdir -p "$DEST"

python3 - "$RACINE" "$VERSION" "$DEST" <<'PY'
import json
import pathlib
import shutil
import sys

racine = pathlib.Path(sys.argv[1])
version = sys.argv[2]
dest = pathlib.Path(sys.argv[3])
liste = json.loads((racine / "site" / "telechargements.json").read_text())
attendus = {}
for entree in liste["fichiers"]:
    nom = entree["nom"].replace("{version}", version)
    source = (racine / entree["source"].replace("{version}", version))
    if not source.is_file() and "/" in entree["source"]:
        # Les artefacts GitHub peuvent arriver à plat ou par architecture.
        candidats = list((racine / "dist").rglob(source.name))
        if candidats:
            source = candidats[0]
    if not source.is_file():
        sys.exit(f"ERREUR : fichier attendu absent : {source}")
    shutil.copyfile(source, dest / nom)
    attendus[nom] = source
    print(f"OK : {nom}")
if not attendus:
    sys.exit("ERREUR : liste de téléchargements vide")
PY

if [ -f "$RACINE/dist/images.txt" ]; then
	install -m 0644 "$RACINE/dist/images.txt" "$DEST/images.txt"
else
	alt=$(find "$RACINE/dist" -type f -name images.txt | head -n 1)
	[ -n "$alt" ] || { echo "ERREUR : images.txt absent" >&2; exit 1; }
	install -m 0644 "$alt" "$DEST/images.txt"
fi

(
	cd "$DEST"
	find . -maxdepth 1 -type f ! -name 'SHA256SUMS*' -printf '%f\n' | sort |
		while IFS= read -r f; do sha256sum "$f"; done >SHA256SUMS.tmp
	mv SHA256SUMS.tmp SHA256SUMS
)
echo "OK : release assemblée dans $DEST"
echo "code=0"
