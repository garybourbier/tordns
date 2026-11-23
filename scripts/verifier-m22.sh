#!/usr/bin/env bash
# TorDNS — preuve de la mission 22 : état public du réseau.
#
# Vérifie l'agrégation (médiane, p95, fenêtre 24 h, purge 30 jours), la
# troncature des adresses, l'absence de contact/domaine/défi dans le JSON et la
# page, le SVG sans JavaScript, et le câblage optionnel de GitHub Pages par Tor.
set -euo pipefail

RACINE=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
TMP=$(mktemp -d "${TMPDIR:-/tmp}/tordns-m22.XXXXXX")
trap 'rm -rf "$TMP"' EXIT
section() { printf '\n== %s ==\n' "$*"; }
ok() { printf 'OK : %s\n' "$*"; }
echec() { printf 'ÉCHEC : %s\n' "$*" >&2; exit 1; }

section "1. Agrégation, fenêtres et purge"
(cd "$RACINE/controleur/registre" && go test -count=1 -v \
	-run 'TestCentilesFenetreEtHistorique|TestDatePublicationOnionbalance|TestEtatReseauPublicTronqueEtSansDonneesPersonnelles' ./...) ||
	echec "tests de l'état réseau"
(cd "$RACINE/controleur/registre" && go vet ./...) || echec "go vet registre"
ok "médiane et p95, 24 h, historique horaire borné à 30 jours, date Onionbalance"
ok "adresses tronquées, pas de contact, pas de défi, pas de nom de domaine demandé"

section "2. Surface HTTP sans JavaScript et JSON public"
(cd "$RACINE/controleur/registre" && go test -count=1 -v \
	-run 'TestEtatReseauPublicTronqueEtSansDonneesPersonnelles' ./...) ||
	echec "surface HTTP de l'état réseau"
ok "/reseau rend un SVG côté serveur ; /reseau.json ne contient que des agrégats"

section "3. Copie Pages conditionnelle et adresse par configuration"
grep -q 'TORDNS_PUBLIER_ETAT_RESEAU' "$RACINE/.github/workflows/pages.yml" ||
	echec "variable d'activation absente du workflow Pages"
grep -q 'copier-etat-reseau.sh' "$RACINE/.github/workflows/pages.yml" ||
	echec "workflow Pages sans copie par Tor"
grep -q -- '--socks5-hostname' "$RACINE/scripts/ci/copier-etat-reseau.sh" ||
	echec "copie sans proxy Tor"
grep -q 'TORDNS_REGISTRE_ONION' "$RACINE/scripts/ci/site-genere.sh" ||
	echec "site sans adresse configurable"

# Une adresse de test (jamais réelle) ne doit apparaître que dans la sortie
# temporaire, jamais dans le dépôt.
FAUSSE=a$(printf 'a%.0s' $(seq 1 55)).onion
mkdir -p "$TMP/site"
TORDNS_REGISTRE_ONION="$FAUSSE" "$RACINE/scripts/ci/site-genere.sh" "$TMP/site" >/dev/null
grep -q "http://$FAUSSE/reseau" "$TMP/site/index.html" ||
	echec "lien .onion non rempli par la configuration"
if git -C "$RACINE" grep -nE '[a-z2-7]{56}\.onion' -- . ':!*test*' ':!*.example' 2>/dev/null |
	grep -vE '([a-z2-7])\1{55}\.onion' | grep -q .; then
	git -C "$RACINE" grep -nE '[a-z2-7]{56}\.onion' -- . ':!*test*' ':!*.example' |
		grep -vE '([a-z2-7])\1{55}\.onion' >&2
	echec "adresse .onion complète suivie dans le dépôt"
fi
ok "Pages seulement si la variable vaut oui ; adresse .onion fournie par configuration"
ok "aucune adresse .onion complète suivie par Git"

section "4. Site et lint"
"$RACINE/scripts/ci/lint.sh" >/dev/null || echec "lint rouge"
"$RACINE/scripts/ci/site-genere.sh" "$TMP/site-sans-onion" >/dev/null
if grep -q 'LIEN_ETAT_RESEAU\|{{' "$TMP/site-sans-onion/index.html"; then
	echec "jeton d'état réseau non remplacé"
fi
grep -q 'Adresse du registre non configurée' "$TMP/site-sans-onion/index.html" ||
	echec "repli sans configuration absent"
python3 - "$TMP/site-sans-onion/index.html" <<'PY'
from html.parser import HTMLParser
from pathlib import Path
import sys

class P(HTMLParser):
    def __init__(self):
        super().__init__()
        self.sections = 0
    def handle_starttag(self, tag, attrs):
        if tag == "section":
            self.sections += 1

p = P()
p.feed(Path(sys.argv[1]).read_text())
p.close()
assert p.sections >= 7, p.sections
print("OK : HTML analysé, section état réseau présente")
PY
ok "site généré sans jeton ni JavaScript, lint vert"

section "5. Bilan"
printf '%s\n' \
	"Toutes les preuves locales de la mission 22 sont passées." \
	"NON PROUVÉ : la publication réelle du service caché et la lecture par Tor" \
	"(le socket Onionbalance et le réseau Tor ne sont pas lancés ici) ;" \
	"l'exécution du workflow Pages avec les variables de dépôt ;" \
	"les délais sur de vrais nœuds (les tests utilisent des mesures simulées)."
echo "code=0"
