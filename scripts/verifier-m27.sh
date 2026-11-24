#!/usr/bin/env bash
# Preuves exécutables de la mission 27 (dossier d'audit de sécurité).
set -euo pipefail

RACINE=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$RACINE"
echec() { echo "ÉCHEC : $*" >&2; exit 1; }
ok() { echo "OK : $*"; }
section() { printf '\n== %s ==\n' "$*"; }

DOSSIER=docs/securite
DOCS=("$DOSSIER/modele-de-menace.md" "$DOSSIER/perimetre-audit.md"
	"$DOSSIER/problemes-connus.md" "$DOSSIER/demande-otf.md" "SECURITY.md")

section "1. Documents présents et structurés"
for f in "${DOCS[@]}"; do
	[ -s "$f" ] || echec "document absent ou vide : $f"
done
grep -q '^## Actifs' "$DOSSIER/modele-de-menace.md" ||
	echec "modèle de menace : section Actifs absente"
grep -q '^## Adversaires et défenses' "$DOSSIER/modele-de-menace.md" ||
	echec "modèle de menace : adversaires absents"
grep -q '^## Composants dans le périmètre' "$DOSSIER/perimetre-audit.md" ||
	echec "périmètre : composants absents"
grep -q '^## Questions précises pour l' "$DOSSIER/perimetre-audit.md" ||
	echec "périmètre : questions à l'auditeur absentes"
grep -q '^## Gravité haute' "$DOSSIER/problemes-connus.md" ||
	echec "problèmes connus : classement par gravité absent"
grep -qi '^## What we ask for' "$DOSSIER/demande-otf.md" ||
	echec "demande OTF : objet de la demande absent"
ok "quatre documents d'audit et SECURITY.md non vides, sections attendues"

grep -q 'signalement privé de GitHub' SECURITY.md ||
	echec "SECURITY.md : signalement privé absent"
grep -q '^## Versions prises en charge' SECURITY.md ||
	echec "SECURITY.md : versions prises en charge absentes"
grep -q '^## Délai de réponse' SECURITY.md ||
	echec "SECURITY.md : délai de réponse absent"
grep -q '90 jours' SECURITY.md ||
	echec "SECURITY.md : délai de divulgation coordonnée absent"
grep -q 'docs/securite/' SECURITY.md ||
	echec "SECURITY.md : renvoi vers docs/securite/ absent"
ok "SECURITY.md : signalement privé, versions, délais, renvoi au dossier"

section "2. Chaque chemin cité existe"
python3 - "$RACINE" "${DOCS[@]}" <<'PY'
import pathlib
import re
import sys

racine = pathlib.Path(sys.argv[1])
documents = sys.argv[2:]
manquants = []
vus = 0
motif = re.compile(r"`([^`\s]+)`")
for nom in documents:
    texte = (racine / nom).read_text()
    for brut in motif.findall(texte):
        if brut.startswith(("http://", "https://", "git@", "sha256:")):
            continue
        if brut.startswith("-") or "..." in brut or "…" in brut or "NN" in brut:
            continue
        candidat = brut.rstrip(".,;:)")
        if "/" not in candidat:
            continue
        if any(c in candidat for c in "*{}<>[]$"):
            continue
        vus += 1
        if not (racine / candidat).exists():
            manquants.append(f"{nom} : {candidat}")
if manquants:
    print("chemins cités inexistants :")
    for m in manquants:
        print("  " + m)
    raise SystemExit(1)
print(f"OK : {vus} chemins cités dans les documents existent")
PY

section "3. Chaque problème connu renvoie au journal"
python3 - "$RACINE" "$DOSSIER/problemes-connus.md" <<'PY'
import pathlib
import re
import sys

racine = pathlib.Path(sys.argv[1])
texte = (racine / sys.argv[2]).read_text()
journal = (racine / "docs/missions/journal.md").read_text()
missions = {int(n) for n in re.findall(r"^## Mission (\d+)", journal, re.M)}
lignes = texte.splitlines()
sans_ref = []
for i, ligne in enumerate(lignes):
    if not ligne.startswith("- **"):
        continue
    bloc = " ".join(lignes[i:i + 6])
    if "journal" not in bloc:
        sans_ref.append(ligne[:70])
refs = {int(n) for n in re.findall(r"journal, missions? ([\d ,et]+)", texte)
        for n in re.findall(r"\d+", n)}
inconnues = sorted(r for r in refs if r not in missions)
if sans_ref:
    print("problèmes sans renvoi au journal :")
    for l in sans_ref:
        print("  " + l)
    raise SystemExit(1)
if inconnues:
    print(f"missions citées absentes du journal : {inconnues}")
    raise SystemExit(1)
print(f"OK : chaque problème renvoie au journal ; {len(refs)} missions citées, toutes présentes")
PY

section "4. Aucun secret, aucune adresse réelle, aucune donnée personnelle"
if grep -RnE '(BEGIN [A-Z ]*PRIVATE KEY|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-)' "${DOCS[@]}"; then
	echec "secret détecté dans le dossier d'audit"
fi
# Une adresse .onion complète (56 caractères base32) est interdite ; les
# gabarits « <adresse>.onion » restent autorisés.
if grep -RnE '\b[a-z2-7]{52,56}\.onion\b' "${DOCS[@]}"; then
	echec "adresse .onion réelle détectée"
fi
if grep -RnEilo '[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}' "${DOCS[@]}"; then
	echec "adresse électronique détectée"
fi
ok "aucune clé, aucune adresse .onion complète, aucun courriel"

section "5. Le dossier reste utilisable hors ligne"
grep -q 'scripts/verifier-m11.sh' "$DOSSIER/perimetre-audit.md" ||
	echec "périmètre : vérificateurs de preuve non cités"
grep -q 'commit' "$DOSSIER/perimetre-audit.md" ||
	echec "périmètre : commit à auditer non mentionné"
grep -qi 'hors périmètre' "$DOSSIER/perimetre-audit.md" ||
	echec "périmètre : hors périmètre non mentionné"
grep -q 'Please do not open a public issue' "$DOSSIER/demande-otf.md" ||
	echec "demande OTF : consigne de non-divulgation absente"
ok "périmètre, commit, hors périmètre et consigne de contact présents"

echo
echo "code=0"
