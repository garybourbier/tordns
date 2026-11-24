#!/usr/bin/env bash
# Récupère les deux dépendances Java du client depuis Maven Central.
#
# F-Droid refuse tout .jar versionné dans le code source : les jars ne sont
# donc plus dans le dépôt, ils arrivent ici dans build/libs/ avec une empreinte
# SHA-256 épinglée. Le cache sert aux constructions suivantes et fonctionne
# hors ligne dès que les deux fichiers sont présents et corrects.
set -euo pipefail

RACINE=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SORTIE="${LIBRAIRIES:-$RACINE/build/libs}"
DEPOT="${DEPOT_MAVEN:-https://repo1.maven.org/maven2}"

# nom|chemin Maven|SHA-256 (publié par Maven Central, vérifié le 24/11/2026)
DEPENDANCES=(
	"dnsjava-3.6.3.jar|dnsjava/dnsjava/3.6.3/dnsjava-3.6.3.jar|ce279b5acb753f58661756b6dcacdcc4dee76748cff04d2abf14edcc7e26a8de"
	"slf4j-api-2.0.16.jar|org/slf4j/slf4j-api/2.0.16/slf4j-api-2.0.16.jar|a12578dde1ba00bd9b816d388a0b879928d00bab3c83c240f7013bf4196c579a"
)

mkdir -p "$SORTIE"

for entree in "${DEPENDANCES[@]}"; do
	IFS='|' read -r nom chemin empreinte <<<"$entree"
	cible="$SORTIE/$nom"
	if [ -f "$cible" ] && [ "$(sha256sum "$cible" | cut -d' ' -f1)" = "$empreinte" ]; then
		echo "OK : $nom déjà présent et vérifié"
		continue
	fi
	tmp="$cible.partiel"
	rm -f "$tmp"
	curl -sSfL --retry 3 --max-time 120 -o "$tmp" "$DEPOT/$chemin" || {
		echo "ERREUR : téléchargement impossible : $DEPOT/$chemin" >&2
		rm -f "$tmp"
		exit 1
	}
	obtenue=$(sha256sum "$tmp" | cut -d' ' -f1)
	if [ "$obtenue" != "$empreinte" ]; then
		echo "ERREUR : empreinte inattendue pour $nom : $obtenue" >&2
		rm -f "$tmp"
		exit 1
	fi
	mv "$tmp" "$cible"
	echo "OK : $nom téléchargé depuis Maven Central, empreinte vérifiée"
done
