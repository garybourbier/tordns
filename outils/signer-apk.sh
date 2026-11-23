#!/bin/sh
# TorDNS — signe les APK d'une release avec la clé de Gary (Mission 16).
#
#   outils/signer-apk.sh --cle /hors/depot/release.jks --alias tordns \
#       --mot-de-passe /hors/depot/motdepasse.txt \
#       --sortie dist/apk-signes apk...
#
# La clé et le mot de passe restent hors du dépôt. Le script ne les affiche
# jamais et utilise des fichiers de mot de passe pour apksigner.
set -eu

PROG=$(basename "$0")
CLE=
ALIAS=
MOT_DE_PASSE=
SORTIE=dist/apk-signes
APKSIGNER=${APKSIGNER:-apksigner}

usage() {
	cat <<EOF
Usage : $PROG --cle <keystore> --alias <alias> --mot-de-passe <fichier> \\
	[--sortie <dossier>] [--apksigner <binaire>] apk...

Signe chaque APK, vérifie la signature avec apksigner verify, puis recalcule
SHA256SUMS dans le dossier de sortie. Aucune clé n'est copiée dans le dépôt.
EOF
}

die() { printf 'ERREUR : %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
	case $1 in
	--cle) [ $# -ge 2 ] || die "--cle exige un chemin"; CLE=$2; shift 2 ;;
	--alias) [ $# -ge 2 ] || die "--alias exige un nom"; ALIAS=$2; shift 2 ;;
	--mot-de-passe) [ $# -ge 2 ] || die "--mot-de-passe exige un fichier"; MOT_DE_PASSE=$2; shift 2 ;;
	--sortie) [ $# -ge 2 ] || die "--sortie exige un dossier"; SORTIE=$2; shift 2 ;;
	--apksigner) [ $# -ge 2 ] || die "--apksigner exige un binaire"; APKSIGNER=$2; shift 2 ;;
	-h | --help) usage; exit 0 ;;
	--) shift; break ;;
	-*) die "option inconnue : $1" ;;
	*) break ;;
	esac
done

[ -n "$CLE" ] || die "--cle obligatoire"
[ -n "$ALIAS" ] || die "--alias obligatoire"
[ -n "$MOT_DE_PASSE" ] || die "--mot-de-passe obligatoire (fichier hors dépôt)"
[ -r "$CLE" ] || die "keystore illisible : $CLE"
[ -r "$MOT_DE_PASSE" ] || die "fichier de mot de passe illisible : $MOT_DE_PASSE"
command -v "$APKSIGNER" >/dev/null 2>&1 || die "apksigner absent : $APKSIGNER"
[ $# -gt 0 ] || die "aucun APK fourni"

mkdir -p "$SORTIE"
for apk in "$@"; do
	[ -s "$apk" ] || die "APK absent : $apk"
	base=$(basename "$apk")
	nom=${base%-NON-SIGNE-POUR-PUBLICATION.apk}
	case $nom in
	*.apk) destination="$SORTIE/$nom" ;;
	*) destination="$SORTIE/$nom.apk" ;;
	esac
	printf 'Signature de %s…\n' "$base"
	"$APKSIGNER" sign --ks "$CLE" --ks-key-alias "$ALIAS" \
		--ks-pass "file:$MOT_DE_PASSE" --key-pass "file:$MOT_DE_PASSE" \
		--in "$apk" --out "$destination"
	"$APKSIGNER" verify --verbose "$destination" >/dev/null ||
		die "signature refusée par apksigner : $destination"
done

# Les sommes portent sur les APK signés, pas sur les fichiers d'entrée.
(
	cd "$SORTIE"
	find . -maxdepth 1 -type f -name '*.apk' -printf '%f\n' | sort |
		while IFS= read -r f; do sha256sum "$f"; done >SHA256SUMS
)
echo "OK : APK signés dans $SORTIE (SHA256SUMS recalculé)"
exit 0
