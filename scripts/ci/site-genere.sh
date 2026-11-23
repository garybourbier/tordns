#!/usr/bin/env bash
# TorDNS — rend les pages statiques du site depuis les gabarits et
# site/telechargements.json (source unique des noms de fichiers).
#   scripts/ci/site-genere.sh [dossier-de-sortie]
# Sans argument, écrit site/index.html et site/en/index.html (versions
# commitées, contrôlées par scripts/verifier-m17.sh).
set -euo pipefail

RACINE=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
SORTIE=${1:-"$RACINE/site"}
mkdir -p "$SORTIE/en"

python3 - "$RACINE" "$SORTIE" <<'PY'
import json
import pathlib
import re
import sys

racine = pathlib.Path(sys.argv[1])
sortie = pathlib.Path(sys.argv[2])
data = json.loads((racine / "site" / "telechargements.json").read_text())
version = data["version"]
base = data["release_base"]
noms = {e["cle"]: e["nom"].replace("{version}", version) for e in data["fichiers"]}
liens = {cle: base + nom for cle, nom in noms.items()}

pages = [
    ("index.html", racine / "site" / "gabarits" / "index.html", sortie / "index.html", ""),
    ("en/index.html", racine / "site" / "gabarits" / "en.html", sortie / "en" / "index.html", "../"),
]

def remplacer(texte, racine_rel):
    def lien(m):
        cle = m.group(1)
        if cle not in liens:
            raise SystemExit(f"ERREUR : téléchargement inconnu : {cle}")
        return liens[cle]

    def nom(m):
        cle = m.group(1)
        if cle not in noms:
            raise SystemExit(f"ERREUR : téléchargement inconnu : {cle}")
        return noms[cle]

    texte = texte.replace("{{VERSION}}", version)
    texte = texte.replace("{{RACINE}}", racine_rel)
    texte = texte.replace("{{SOMMES}}", base + data["sommes"])
    texte = re.sub(r"\{\{LIEN:([^}]+)\}\}", lien, texte)
    texte = re.sub(r"\{\{NOM:([^}]+)\}\}", nom, texte)
    if "{{" in texte:
        raise SystemExit("ERREUR : jeton non remplacé dans le gabarit")
    return texte

for _, source, destination, racine_rel in pages:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(remplacer(source.read_text(), racine_rel))
    print(f"OK : {destination}")
PY
