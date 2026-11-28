#!/usr/bin/env bash
# Compile et teste le client iOS. Appelé par le job `ios` du workflow CI sur
# un runner macOS : ici (Linux) seules les parties Rust sont reproductibles.
#
# Options (variables d'environnement) :
#   TORDNS_TEAM_ID            identifiant d'équipe Apple, signature si présent ;
#   TORDNS_APPLE_ID           compte Apple pour l'envoi TestFlight ;
#   TORDNS_APPLE_MOT_DE_PASSE mot de passe d'application correspondant.
# Sans ces variables, la compilation pour le simulateur et les tests tournent,
# l'archive signée et l'envoi TestFlight sont sautés.
set -euo pipefail

RACINE=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
CLIENT="$RACINE/client-ios"
DESTINATION="${DESTINATION:-}"

etape() { printf '\n== %s ==\n' "$1"; }

if [ "$(uname -s)" != Darwin ]; then
	echo "ERREUR : la CI iOS exige macOS (xcodebuild, xcodegen, SDK iOS)." >&2
	exit 1
fi
for outil in xcodebuild xcodegen cargo; do
	command -v "$outil" >/dev/null || {
		echo "ERREUR : $outil manquant." >&2
		exit 1
	}
done

# Le nom des simulateurs dépend de l'image du runner : prendre le premier
# iPhone disponible plutôt qu'un modèle figé (iPhone 16 manque aux images 26).
if [ -z "$DESTINATION" ]; then
	NOM=$(xcrun simctl list devices available 2>/dev/null |
		awk -F'[()]' '/^[[:space:]]*iPhone /{sub(/[[:space:]]+$/, "", $1); sub(/^[[:space:]]+/, "", $1); print $1; exit}')
	[ -n "$NOM" ] || NOM=iPhone 16
	DESTINATION="platform=iOS Simulator,name=$NOM"
fi
echo "Simulateur : $DESTINATION"

etape "1. Tests du crate partagé et du pont C (hôte)"
(cd "$RACINE/outils/arti-rust" && cargo test --locked --quiet)
(cd "$CLIENT/rust" && cargo test --locked --quiet)

etape "2. Projet Xcode"
(cd "$CLIENT" && xcodegen generate --spec project.yml --quiet)

etape "3. Compilation pour le simulateur"
(cd "$CLIENT" && xcodebuild \
	-project TorDNS.xcodeproj \
	-scheme TorDNS \
	-configuration Debug \
	-destination "$DESTINATION" \
	CODE_SIGNING_ALLOWED=NO \
	build)

etape "4. Tests sur le simulateur"
(cd "$CLIENT" && xcodebuild \
	-project TorDNS.xcodeproj \
	-scheme TorDNS \
	-configuration Debug \
	-destination "$DESTINATION" \
	CODE_SIGNING_ALLOWED=NO \
	test)

if [ -n "${TORDNS_TEAM_ID:-}" ] && [ -n "${TORDNS_APPLE_ID:-}" ] &&
	[ -n "${TORDNS_APPLE_MOT_DE_PASSE:-}" ]; then
	etape "5. Archive signée et envoi TestFlight"
	(cd "$CLIENT" && xcodebuild \
		-project TorDNS.xcodeproj \
		-scheme TorDNS \
		-configuration Release \
		-destination "generic/platform=iOS" \
		-archivePath "$CLIENT/build/TorDNS.xcarchive" \
		TORDNS_TEAM_ID="$TORDNS_TEAM_ID" \
		archive)
	(cd "$CLIENT" && xcodebuild -exportArchive \
		-archivePath "$CLIENT/build/TorDNS.xcarchive" \
		-exportPath "$CLIENT/build/export" \
		-exportOptionsPlist Config/ExportOptions.plist)
	xcrun altool --upload-app \
		--type ios \
		--file "$CLIENT/build/export/TorDNS.ipa" \
		--username "$TORDNS_APPLE_ID" \
		--password "$TORDNS_APPLE_MOT_DE_PASSE"
else
	etape "5. Archive signée : sautée (secrets Apple absents)"
	echo "NON PROUVÉ : aucun certificat ni mot de passe d'application fourni."
fi

etape "Terminé"
