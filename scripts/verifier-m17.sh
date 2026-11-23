#!/usr/bin/env bash
# Preuves exécutables de la mission 17 (site statique, liens, accessibilité).
set -euo pipefail

RACINE=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$RACINE"
TMP=$(mktemp -d "${TMPDIR:-/tmp}/tordns-m17.XXXXXX")
trap 'rm -rf "$TMP"' EXIT
echec() { echo "ÉCHEC : $*" >&2; exit 1; }
section() { printf '\n== %s ==\n' "$*"; }

section "1. Workflow Pages et génération"
./scripts/ci/lint.sh >/dev/null || echec "lint (actionlint) rouge"
grep -q 'pages: write' .github/workflows/pages.yml || echec "permission pages absente"
grep -q 'id-token: write' .github/workflows/pages.yml || echec "permission id-token absente"
grep -q 'upload-pages-artifact' .github/workflows/pages.yml || echec "artefact Pages absent"
grep -q 'deploy-pages' .github/workflows/pages.yml || echec "déploiement Pages absent"
grep -q 'site/\*\*' .github/workflows/pages.yml || echec "déclencheur site absent"
echo "OK : Pages sur push master touchant site/, permissions ciblées"

./scripts/ci/site-genere.sh "$TMP/genere" >/dev/null
diff -q site/index.html "$TMP/genere/index.html" >/dev/null || echec "index.html non régénéré"
diff -q site/en/index.html "$TMP/genere/en/index.html" >/dev/null || echec "page anglaise non régénérée"
grep -q '{{' site/index.html site/en/index.html && echec "jeton non remplacé"
echo "OK : pages françaises et anglaises régénérées à l'identique"

section "2. Source unique des noms et liens"
python3 - "$RACINE" <<'PY'
import json
import pathlib
import re
import sys

racine = pathlib.Path(sys.argv[1])
data = json.loads((racine / "site" / "telechargements.json").read_text())
version = (racine / "noeud" / "VERSION").read_text().strip()
assert data["version"] == version, f"version du site {data['version']} != noeud/VERSION {version}"
noms = {e["nom"].replace("{version}", version) for e in data["fichiers"]}
for page in ("index.html", "en/index.html"):
    texte = (racine / "site" / page).read_text()
    liens = set(re.findall(r"releases/latest/download/([^\"]+)", texte))
    inconnus = liens - noms - {"SHA256SUMS"}
    assert not inconnus, f"{page} : liens inconnus {sorted(inconnus)}"
    manquants = noms - liens
    assert not manquants, f"{page} : téléchargements absents {sorted(manquants)}"
print(f"OK : {len(noms)} fichiers, liens des deux pages identiques à telechargements.json")
PY
grep -q 'telechargements.json' scripts/ci/release-assembler.sh || echec "assembler sans JSON"
grep -q 'telechargements.json' scripts/ci/release-locale.sh || echec "release locale sans JSON"
echo "OK : release et site partagent la même liste"

section "3. Contenu local et sans traceur"
if grep -RhoE 'https?://[^"< )]+' site | grep -vE '^https://github\.com/' | grep -q .; then
	grep -RhoE 'https?://[^"< )]+' site | grep -vE '^https://github\.com/' | sort -u
	echec "URL externe hors github.com"
fi
grep -RqiE 'fetch\(|XMLHttpRequest|document\.cookie|localStorage|sessionStorage|google-analytics' site &&
	echec "traceur, cookie ou stockage détecté"
grep -Rqi 'prefers-color-scheme' site/style.css || echec "thème sombre absent"
grep -q 'viewport' site/index.html || echec "meta viewport absent"
grep -q 'aria-label' site/index.html || echec "repères ARIA absents"
grep -q '<title id="schema-titre">' site/index.html || echec "titre SVG absent"
grep -q 'security/advisories/new' SECURITY.md || echec "signalement GitHub absent"
grep -Eq '[[:alnum:]._%+-]+@[[:alnum:].-]+\.[a-z]{2,}' SECURITY.md && echec "adresse e-mail personnelle dans SECURITY.md"
echo "OK : pages locales, aucun traceur ni URL hors github.com, SECURITY.md sans e-mail"

section "4. Validation HTML et captures"
if command -v tidy >/dev/null 2>&1; then
	tidy -qe site/index.html site/en/index.html >"$TMP/tidy.log" 2>&1 ||
		{ cat "$TMP/tidy.log"; echec "tidy a signalé une erreur"; }
	echo "OK : tidy"
else
	python3 - <<'PY'
from html.parser import HTMLParser
from pathlib import Path

class Verif(HTMLParser):
    def __init__(self):
        super().__init__()
        self.titres = 0

    def handle_starttag(self, balise, attrs):
        if balise == "title":
            self.titres += 1

for page in ("site/index.html", "site/en/index.html"):
    p = Verif()
    p.feed(Path(page).read_text())
    p.close()
    assert p.titres >= 1, page
print("OK : HTML analysé (tidy/vnu absents)")
PY
fi

command -v chromium >/dev/null 2>&1 || echec "chromium absent"
mkdir -p dist/preuves
for page in index.html en/index.html; do
	for largeur in 360 1280; do
		nom=$(printf '%s' "$page" | tr '/' '-')
		mesure=$(python3 scripts/ci/site-capture.py "site/$page" "$largeur" \
			"dist/preuves/site-${nom%.html}-$largeur.png")
		echo "$mesure"
		printf '%s' "$mesure" | python3 -c '
import json, sys
m = json.load(sys.stdin)
assert m["scrollWidth"] <= m["largeur"], m
' || echec "défilement horizontal : $mesure"
		echo "OK : $page à $largeur px sans débordement"
	done
done

section "5. Bilan"
echo "Toutes les preuves locales de la mission 17 sont passées."
echo "NON PROUVÉ — la page en ligne : Gary doit activer Pages avec la source"
echo "« GitHub Actions » dans les réglages du dépôt, puis vérifier l'URL publiée."
echo "code=0"
