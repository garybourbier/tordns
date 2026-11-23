#!/usr/bin/env bash
# shellcheck disable=SC1112
# TorDNS — preuve de la mission 19 : restes de la relecture du 23/11.
#
# 1. Sonde du registre : intersection d'adresses, doute non signé compté par
#    domaine distinct, mensonge sur réponse signée ou RCODE/AD différent.
# 2. Version rejetée retenue par les mises à jour Linux, nœud et Windows :
#    pas de nouvelle tentative de la même version, version supérieure essayée.
# 3. Rejeu de M10, M11 et M12 sur l'arbre final.
#
# Tout est local : aucun Tor, aucun serveur de Gary, aucun secret.
set -euo pipefail

RACINE=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
TMP=$(mktemp -d "${TMPDIR:-/tmp}/tordns-m19.XXXXXX")
trap 'rm -rf "$TMP"' EXIT

section() { printf '\n== %s ==\n' "$*"; }
ok() { printf 'OK : %s\n' "$*"; }
echec() { printf 'ÉCHEC : %s\n' "$*" >&2; exit 1; }

section "1. Registre : tourniquet accepté, mensonges signés refusés"
(cd "$RACINE/controleur/registre" && go test -count=1 -v \
	-run 'TestSondeTourniquetIntersection|TestAdresseInventeeSurZoneSigneeEstMensonge|TestDnssecFailedResoluEstMensonge|TestDouteuxNEvineQuApresNDomaines|TestDouteuxEvinceUnAdmis' ./...) ||
	echec "tests de la sonde du registre"
(cd "$RACINE/controleur/registre" && go vet ./...) || echec "go vet registre"
ok "intersection non vide acceptée ; adresse signée inventée et dnssec-failed.org refusés"
ok "N doutes non signés sur des domaines distincts : candidat non admis puis disqualifié, admis évincé"
ok "les empreintes de domaines ne sont pas publiées dans /etat"

section "2. Client Linux : version rejetée non retentée, v3 saine installée"
(cd "$RACINE/client-linux" && go test -count=1 -v \
	-run 'TestClientSystemdEchoueRetourArriere|TestClientVersionRejeteePuisV3' ./cmd/maj) ||
	echec "tests de mise à jour du client Linux"
ok "v2 cassée : retour v1, rejetee=2, second passage sans redémarrage ; v3 saine installée"

section "3. Nœud : version rejetée non retentée, v3 saine installée"
(cd "$RACINE/noeud/maj" && go test -count=1 -v \
	-run 'TestImageCasseeRetourArriere|TestVersionRejeteePuisV3' ./...) ||
	echec "tests de mise à jour du nœud"
ok "v2 cassée : v1 rétablie, rejetee=2, second passage sans docker ; v3 saine installée"

section "4. Client Windows : version rejetée non retentée, v3 saine installée"
(cd "$RACINE/client-windows" && cargo test --lib maj::tests -- --test-threads=1) ||
	echec "tests de mise à jour Windows"
ok "v2 cassée : retour à l'installateur précédent, rejetee=2 ; v3 saine installée"

section "5. Rejeu des missions 10, 11 et 12"
for mission in 10 11 12; do
	log="$TMP/m$mission.log"
	if "$RACINE/scripts/verifier-m$mission.sh" >"$log" 2>&1; then
		tail -n 3 "$log"
		ok "verifier-m$mission.sh rejoué, code=0"
	else
		code=$?
		cat "$log" >&2
		echec "verifier-m$mission.sh rouge (code=$code)"
	fi
done

section "6. Bilan"
printf '%s\n' \
	'Toutes les preuves exécutables ici sont passées.' \
	'NON PROUVÉ : la sonde contre de vrais CDN et tourniquets (les réponses' \
	'distinctes sont simulées) et contre l’Internet réel (dnssec-failed.org est' \
	'imité par un résolveur local) ; le seuil de doutes sur des domaines réels ;' \
	'un redémarrage systemd réel (systemctl est remplacé dans les tests Go) ;' \
	'un service Windows réel et ses droits NTFS (le test Rust ne lance pas' \
	'l’installateur NSIS) ; le transport Tor des mises à jour (les tests' \
	'd’installation utilisent un serveur HTTP local).'

echo "code=0"
