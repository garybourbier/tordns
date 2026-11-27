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
# Les deux ancres du roulement (20326 et 38696) sont prouvées par le test des
# ancres livrées : il ÉCHOUE si une seule est présente, ou si ses octets ne
# sont plus ceux de l'IANA. Aucun grep sur le source ne remplace ce test.
ok "Android : les deux ancres IANA (20326, 38696) sont lues et contrôlées par le test"

section "2. Windows : zones non signées prouvées par NSEC/NSEC3 opt-out"
(cd "$RACINE/client-windows" && cargo test --lib dnssec::tests -- --test-threads=1 2>&1) |
    grep -q "test result: ok" || echec "tests DNSSEC Windows"
(cd "$RACINE/client-windows" && cargo test --lib dnssec::tests_ancres -- --test-threads=1 2>&1) |
    grep -q "test result: ok" || echec "tests ancres Windows"
ok "Windows : ancres du roulement (38696 + défauts hickory), NSEC/NSEC3 opt-out et réponses négatives testés"

section "3. Registre : contrôleur, indisponibilités, quota, ID aléatoire, rétention"
(cd "$RACINE/controleur/registre" && go test -count=1 ./... 2>&1) |
    grep -q "ok" || echec "tests registre"
(cd "$RACINE/controleur/registre" && go vet ./...) || echec "go vet registre"

# Les 5 corrections sont prouvées par des TESTS DE COMPORTEMENT : un grep
# d'identifiant disait qu'un nom existait, pas que le registre faisait ce qu'il
# faut. Chaque test doit apparaître comme PASS dans la sortie.
registre_tests='TestReferenceInjoignableNAllereAucunCompteur|TestIndisponibilitesConsecutivesPuisEviction|TestQuotaJournalierALaConfirmation|TestRetentionPurgeCandidatsEtEvinces|TestSondeIdentifiantDNSAleatoire'
sortie_registre=$(cd "$RACINE/controleur/registre" && go test -count=1 -v -run "$registre_tests" ./... 2>&1) || {
    printf '%s\n' "$sortie_registre" >&2
    echec "tests des corrections du registre"
}
for test in TestReferenceInjoignableNAllereAucunCompteur \
            TestIndisponibilitesConsecutivesPuisEviction \
            TestQuotaJournalierALaConfirmation \
            TestRetentionPurgeCandidatsEtEvinces \
            TestSondeIdentifiantDNSAleatoire; do
    grep -q -- "--- PASS: $test" <<<"$sortie_registre" ||
        echec "$test n'a pas été exécuté ou a échoué"
done
ok "Registre : référence injoignable neutre, indispo consécutives remises à zéro et éviction, quota à la confirmation, rétention, ID DNS aléatoire"

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

# Diagnostic DNSSEC réel : outil compilé, requête DO/A testée hors ligne.
[ -f "$RACINE/client-linux/cmd/verifier-dnssec/main.go" ] ||
    echec "outil tordns-verifier-dnssec absent"
(cd "$RACINE/client-linux" && go vet ./cmd/verifier-dnssec) || echec "go vet verifier-dnssec"
(cd "$RACINE/client-linux" && go test -count=1 ./relais -run '^TestValiderNom' 2>&1) |
    grep -q "^ok" || echec "test hors ligne du diagnostic DNSSEC"
ok "Diagnostic DNSSEC : requête A avec bit DO, refus d'un nom invalide (hors ligne)"

# Le réseau n'est pas exigé par défaut : la preuve réelle du 27/11/2026 est au
# journal. Relancer avec TORDNS_M28_RESEAU=1 pour la refaire maintenant.
if [ "${TORDNS_M28_RESEAU:-}" = "1" ]; then
    (cd "$RACINE/client-linux" && go run ./cmd/verifier-dnssec \
        -doh https://cloudflare-dns.com/dns-query cloudflare.com 2>&1) |
        grep -q "accepté DNSSEC" || echec "nom signé réel non accepté"
    if (cd "$RACINE/client-linux" && go run ./cmd/verifier-dnssec \
        -doh https://cloudflare-dns.com/dns-query dnssec-failed.org 2>&1); then
        echec "nom cassé réel accepté"
    fi
    (cd "$RACINE/client-linux" && go run ./cmd/verifier-dnssec \
        -doh https://cloudflare-dns.com/dns-query google.com 2>&1) |
        grep -q "zone non signée" || echec "zone non signée réelle non reconnue"
    ok "Diagnostic réseau : nom signé accepté, nom cassé refusé, zone non signée reconnue"
else
    ok "Diagnostic réseau non relancé (TORDNS_M28_RESEAU=1 pour l'exiger) ; preuve du 27/11/2026 au journal"
fi

section "6. Textes alignés au code (vérifications de cohérence)"
# Les promesses doivent être dans la doc utilisateur, pas dans la mission.
grep -q "réponse du nœud n'est jamais" "$RACINE/client-linux/README.md" ||
    echec "promesse « réponse jamais relayée » absente du README client Linux"
grep -q "délégation sans DS" "$RACINE/client-linux/README.md" ||
    echec "promesse « délégation sans DS » absente du README client Linux"
grep -q "zone non signée" "$RACINE/client-linux/README.md" ||
    echec "promesse « zone non signée » absente du README client Linux"
# Le diagnostic réel est cité là où l'utilisateur le cherche.
grep -q "tordns-verifier-dnssec" "$RACINE/client-linux/README.md" ||
    echec "diagnostic DNSSEC absent du README client Linux"
# Ce qui n'est pas prouvé ne doit pas être présenté comme prouvé : seuls
# Windows et Android restent non prouvés contre la racine réelle.
grep -q "DNSSEC contre les racines réelles côté Windows et Android" "$RACINE/README.md" ||
    echec "README : limites DNSSEC réelles non explicitées"
ok "README et README client Linux promettent ce que le code tient"

section "7. Calendrier racine et livraison d'une ancre"
DOC="$RACINE/docs/calendrier-racine.md"
[ -f "$DOC" ] || echec "docs/calendrier-racine.md absent"
for attendu in "KSK-2017" "11/01/2027" "22/03/2027" "KSK-2024" "11/10/2026" \
                "38696" "20326" "manifeste"; do
    grep -qF -- "$attendu" "$DOC" || echec "calendrier racine : « $attendu » absent"
done
# Les ancres sont compilées : le document doit le dire, pas promettre une
# livraison à chaud que le manifeste ne permet pas.
grep -q "pas de mise à jour d'ancre" "$DOC" ||
    echec "calendrier racine : absence de livraison à chaud non dite"
ok "Calendrier racine documenté (11/01/2027, 22/03/2027) et livraison par release signée, sans ancre dans le manifeste"

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
    'Diagnostic DNSSEC réel (Linux) : exécuté le 27/11/2026 via DoH direct, voir le journal.' \
    'NON PROUVÉ : DNSSEC contre la racine réelle côté Windows et Android ;' \
    'rotation d'\''ancre racine sur un parc réel (livrée par une release signée, pas par le manifeste) ;' \
    'comportement de vrais nœuds bénévoles sous charge ;' \
    'transport Tor du diagnostic DNSSEC (il utilise HTTPS direct).'

echo "code=0"