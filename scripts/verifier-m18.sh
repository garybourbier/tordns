#!/usr/bin/env bash
# Preuves exécutables de la mission 18 (README à jour, liens et noms de release).
set -euo pipefail

RACINE=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$RACINE"
echec() { echo "ÉCHEC : $*" >&2; exit 1; }
section() { printf '\n== %s ==\n' "$*"; }

section "1. Structure et absence de promesses"
python3 - <<'PY'
from pathlib import Path
import re

racine = Path(".")
texte = Path("README.md").read_text()
titres = ["## Télécharger", "## Démarrage rapide", "## Héberger un nœud",
          "## Architecture", "## Sécurité", "## Développer", "## Historique",
          "## Licence"]
positions = []
for titre in titres:
    assert titre in texte, f"section absente : {titre}"
    positions.append(texte.index(titre))
assert positions == sorted(positions), "sections du README dans le désordre"
assert "gh attestation verify" in texte
assert "SHA256SUMS" in texte
assert "manifeste" in texte.lower()
assert "garybourbier.github.io/tordns" in texte
assert "[LICENSE](LICENSE)" in texte
interdits = ["ultra-sécurisé", "ultra sécurisé", "absolue", "incensurable",
             "zero-log", "sans le moindre"]
for mot in interdits:
    assert mot.lower() not in texte.lower(), f"formulation marketing : {mot}"
assert not re.search(r"[a-z2-7]{56}\.onion", texte)
print("OK : sections ordonnées, vérification, sécurité, historique, licence")
PY

section "2. Liens relatifs existants"
python3 - <<'PY'
from pathlib import Path
import re

lectures = [Path("README.md"), Path("client-linux/README.md"),
            Path("client-windows/README.md"), Path("client-android/README.md"),
            Path("client-macos/README.md"), Path("noeud/README.md")]
for fichier in lectures:
    texte = fichier.read_text()
    for cible in re.findall(r"\]\(([^)]+)\)", texte):
        cible = cible.strip()
        if cible.startswith(("http://", "https://", "#", "mailto:")):
            continue
        chemin = cible.split("#", 1)[0]
        if not chemin:
            continue
        attendu = (fichier.parent / chemin).resolve()
        assert attendu.exists(), f"{fichier} : lien cassé {cible}"
print(f"OK : liens relatifs des {len(lectures)} README existants")
PY

section "3. Noms de téléchargement alignés sur la release"
python3 - <<'PY'
import json
from pathlib import Path
import re

data = json.loads(Path("site/telechargements.json").read_text())
version = Path("noeud/VERSION").read_text().strip()
assert data["version"] == version, "version du site != noeud/VERSION"
noms = {e["nom"].replace("{version}", version) for e in data["fichiers"]}
lien = set(re.findall(r"releases/latest/download/([^)\s]+)", Path("README.md").read_text()))
assert lien == noms, f"README : manquants {sorted(noms - lien)}, inconnus {sorted(lien - noms)}"
workflow = Path(".github/workflows/release.yml").read_text()
assert "release-assembler.sh" in workflow
assert "telechargements.json" in Path("scripts/ci/release-assembler.sh").read_text()
assert "telechargements.json" in Path("scripts/ci/release-locale.sh").read_text()
print(f"OK : {len(noms)} liens README identiques aux noms de release")
PY

section "4. Renvois de téléchargement dans les README de composants"
grep -q 'releases/latest' client-linux/README.md || echec "client-linux ne renvoie pas à la release"
grep -q 'releases/latest' client-windows/README.md || echec "client-windows ne renvoie pas à la release"
grep -q 'releases/latest' client-android/README.md || echec "client-android ne renvoie pas à la release"
grep -q 'releases/latest' client-macos/README.md || echec "client-macos ne renvoie pas à la release"
grep -q 'images.txt' noeud/README.md || echec "noeud sans images GHCR"
grep -q -- '--images ghcr' noeud/README.md || echec "noeud sans option GHCR"
echo "OK : chaque composant renvoie à la release, le nœud documente GHCR"

section "5. Bilan"
echo "Toutes les preuves locales de la mission 18 sont passées."
echo "NON PROUVÉ — l'affichage réel du README sur GitHub et le rendu des badges"
echo "ne sont pas testés ici ; les liens externes ne sont pas visités."
echo "code=0"
