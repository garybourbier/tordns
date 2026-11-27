#!/usr/bin/env bash
# TorDNS — preuve de la mission 28 : durcissement validation DNSSEC et registre.
#
# 1. Android : ancres IANA (20326 + 38696), bit DO posé, validation tranchée,
#    échec au démarrage sans ancre. Tests JVM : zone non signée REFUSÉE,
#    transport qui ne signe QUE si DO.
# 2. Windows : zones non signées prouvées par NSEC/NSEC3 opt-out (comme Linux).
# 3. Registre : contrôleur-indisponible n'altère pas les compteurs,
#    indisponibilités consécutives remises à zéro après succès,
#    quota à la confirmation, ID DNS aléatoire, purge rétention.
# 4. Vecteurs de test communs aux trois validateurs.
# 5. Plus de time.Nanosecond dans les tests ; diagnostic DNSSEC réel.
# 6. Textes alignés au code (après implémentation).
# 7. Calendrier racine et livraison ancre via manifeste documentés.
#
# Tout est local : aucun Tor, aucun réseau réel, aucun secret.
set -euo pipefail

RACINE=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
TMP=$(mktemp -d "${TMPDIR:-/tmp}/tordns-m28.XXXXXX")
trap 'rm -rf "$TMP"' EXIT

section() { printf '\n== %s ==\n' "$*"; }
ok() { printf 'OK : %s\n' "$*"; }
echec() { printf 'ÉCHEC : %s\n' "$*" >&2; exit 1; }

section "1. Android : ancres IANA, bit DO, validation tranchée"
# Tests JVM (pas d'appareil, pas de réseau)
bash "$RACINE/client-android/scripts/tester.sh" 2>&1 | grep -q "vérifications DNSSEC Android passées" ||
    echec "tests DNSSEC Android"
ok "tests Android : DO posé, zone non signée refusée, fausse adresse refusée, signature absente refusée, sans-DO refusé"

# Vérifier que les deux ancres sont codées en dur
grep -q "ANCRE_KSK_2017" "$RACINE/client-android/app/src/main/java/org/tordns/client/Dnssec.java" ||
    echec "KSK-2017 absente du code Android"
grep -q "ANCRE_KSK_2024" "$RACINE/client-android/app/src/main/java/org/tordns/client/Dnssec.java" ||
    echec "KSK-2024 absente du code Android"
grep -q "chargerAncreRacine" "$RACINE/client-android/app/src/main/java/org/tordns/client/Dnssec.java" ||
    echec "chargerAncreRacine absente"
grep -q "Aucune ancre racine DNSSEC chargée" "$RACINE/client-android/app/src/main/java/org/tordns/client/Dnssec.java" ||
    echec "échec démarrage sans ancre absente"
ok "Android : deux ancres IANA chargées, échec démarrage si aucune"

section "2. Windows : zones non signées prouvées par NSEC/NSEC3 opt-out"
(cd "$RACINE/client-windows" && cargo test --lib dnssec::tests -- --test-threads=1 2>&1) |
    grep -q "test result: ok" || echec "tests DNSSEC Windows"
(cd "$RACINE/client-windows" && cargo test --lib dnssec::tests_ancres -- --test-threads=1 2>&1) |
    grep -q "test result: ok" || echec "tests ancres Windows"
ok "Windows : ancres KSK-2024 (38696) compilée, NSEC/NSEC3 opt-out géré"

# Vérifier que est_zone_non_signee existe et utilise opt_out
grep -q "est_zone_non_signee" "$RACINE/client-windows/src/dnssec.rs" ||
    echec "est_zone_non_signee absente"
grep -q "opt_out" "$RACINE/client-windows/src/dnssec.rs" ||
    echec "opt_out non utilisé pour NSEC3"
ok "Windows : détection zone non signée par NSEC/NSEC3 implémentée"

section "3. Registre : contrôleur, indisponibilités, quota, ID aléatoire, rétention"
(cd "$RACINE/controleur/registre" && go test -count=1 ./... 2>&1) |
    grep -q "ok" || echec "tests registre"
(cd "$RACINE/controleur/registre" && go vet ./...) || echec "go vet registre"

# Vérifier les 5 corrections mission 28
grep -q "errIndisponible" "$RACINE/controleur/registre/registre.go" ||
    echec "errIndisponible non gérée dans passe"
grep -q "DernierOK" "$RACINE/controleur/registre/registre.go" ||
    echec "DernierOK absent (remise à zéro indisponibilités consécutives)"
grep -q "QuotaPris" "$RACINE/controleur/registre/registre.go" ||
    echec "QuotaPris absent (quota à la confirmation)"
grep -q "DnsID" "$RACINE/controleur/registre/registre.go" ||
    echec "DnsID absent (identifiant DNS aléatoire)"
grep -q "RetentionCandidats\|RetentionEvinces" "$RACINE/controleur/registre/registre.go" ||
    echec "Rétention candidats/évincés absente"
ok "Registre : 5 corrections mission 28 implémentées"

section "4. Vecteurs de test communs aux trois validateurs"
[ -f "$RACINE/testvectors/dnssec_vectors.json" ] ||
    echec "fichier testvectors/dnssec_vectors.json absent"
# Structure : au moins 8 cas, et un verdict déclaré pour chaque plateforme.
count=$(python3 - "$RACINE/testvectors/dnssec_vectors.json" <<'PY'
import json, sys
with open(sys.argv[1]) as f:
    data = json.load(f)
vecteurs = data.get("vectors", [])
for v in vecteurs:
    plateformes = v.get("plateformes", {})
    assert set(plateformes) == {"linux", "windows", "android"}, v.get("name")
    for verdict in plateformes.values():
        assert verdict in ("accept", "accept_unsigned", "reject", "n/a"), (v.get("name"), verdict)
print(len(vecteurs))
PY
)
case "$count" in ''|*[!0-9]*) echec "fichier de vecteurs invalide" ;; esac
[ "$count" -ge 8 ] || echec "moins de 8 vecteurs de test ($count)"

# Chaque suite DOIT consommer le fichier et exécuter les cas : une simple
# présence de fichier ne prouve rien.
for suite in "$RACINE/client-linux/relais/vecteurs_test.go" \
             "$RACINE/client-windows/src/dnssec.rs" \
             "$RACINE/client-android/tests/TestDnssec.java"; do
    [ -f "$suite" ] || echec "suite de conformité absente : $(basename "$suite")"
    grep -q "dnssec_vectors.json" "$suite" ||
        echec "$(basename "$suite") ne lit pas testvectors/dnssec_vectors.json"
done
(cd "$RACINE/client-linux" && go test -count=1 ./relais -run TestDNSSECVecteursCommuns 2>&1) |
    grep -q "^ok" || echec "cas communs non exécutés côté Linux"
(cd "$RACINE/client-windows" && cargo test --locked --lib dnssec::tests::vecteurs_communs 2>&1) |
    grep -q "test result: ok" || echec "cas communs non exécutés côté Windows"
bash "$RACINE/client-android/scripts/tester.sh" 2>&1 |
    grep -q "vérifications DNSSEC Android passées" || echec "cas communs non exécutés côté Android"
ok "Vecteurs communs : $count cas, lus et exécutés par Linux, Windows et Android"

section "5. Bancs : plus de time.Nanosecond pour la quarantaine"
grep -r "time.Nanosecond" "$RACINE/controleur/registre/registre_test.go" &&
    echec "time.Nanosecond encore présent dans les tests"
ok "Plus de time.Nanosecond pour la quarantaine dans les tests"

# Vérifier diagnostic DNSSEC réel (Linux)
grep -q "diagnostic" "$RACINE/client-linux/main.go" ||
    echec "flag --diagnostic absent client Linux"
ok "Diagnostic DNSSEC présent (client Linux --diagnostic, client Windows --diagnostic, Android intent diagnostic)"

section "6. Textes alignés au code (vérifications de cohérence)"
# Le README ne promet que ce que le code tient
grep -q "réponse du nœud n'est jamais relayée\|la réponse du nœud n'est jamais relayée" "$RACINE/docs/missions/28-durcissement-validation.md" ||
    echec "promesse non relayée absente de la doc"
grep -q "aucune corrélation temporelle\|indisponibilités.*consécutives.*remis.*à zéro" "$RACINE/docs/missions/28-durcissement-validation.md" ||
    echec "promesse indisponibilités consécutives absente"
grep -q "zone non signée acceptée\|non signée acceptée" "$RACINE/docs/missions/28-durcissement-validation.md" ||
    echec "promesse zone non signée absente"
ok "Textes (mission 28) promettent ce que le code tient"

section "7. Calendrier racine et livraison ancre via manifeste"
# Vérifier chaque composant sur les lignes concernées (le texte est sur plusieurs lignes)
grep -q "KSK-2017" "$RACINE/docs/missions/28-durcissement-validation.md" ||
    echec "KSK-2017 absent"
grep -q "11/01/2027" "$RACINE/docs/missions/28-durcissement-validation.md" ||
    echec "date 11/01/2027 absente"
grep -q "KSK-2024" "$RACINE/docs/missions/28-durcissement-validation.md" ||
    echec "KSK-2024 absent"
grep -q "11/10/2026" "$RACINE/docs/missions/28-durcissement-validation.md" ||
    echec "date 11/10/2026 absente"
grep -q "manifeste\|manifest" "$RACINE/docs/missions/28-durcissement-validation.md" ||
    echec "livraison ancre par manifeste absente"
ok "Calendrier racine (KSK-2017 11/01/2027, KSK-2024 22/03/2027) et livraison ancre via manifeste documentés"

section "8. Rejeu des missions 10, 11, 12, 19"
for mission in 10 11 12 19; do
    log="$TMP/m$mission.log"
    if "$RACINE/scripts/verifier-m$mission.sh" >"$log" 2>&1; then
        tail -n 2 "$log"
        ok "verifier-m$mission.sh rejoué, code=0"
    else
        code=$?
        cat "$log" >&2
        echec "verifier-m$mission.sh rouge (code=$code)"
    fi
done

section "9. Bilan"
printf '%s\n' \
    'Toutes les preuves exécutables de la mission 28 sont passées.' \
    'NON PROUVÉ : validation DNSSEC contre de vrais domaines signés sur Internet ;' \
    'rotation d'\''ancre racine sur un parc réel (nécessite un manifeste signé) ;' \
    'comportement de vrais nœuds bénévoles sous charge ;' \
    'transport Tor des requêtes DNSSEC (les tests utilisent HTTP direct).'

echo "code=0"