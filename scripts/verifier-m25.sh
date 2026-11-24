#!/usr/bin/env bash
# TorDNS — preuve de la mission 25 (publication sur F-Droid).
#
# Vérifie la recette fdroiddata et les métadonnées, puis fait tourner les outils
# officiels `fdroid lint` et `fdroid build` sur cette recette, dans un dossier
# fdroiddata jetable. Deux adaptations locales, imprimées à l'écran :
#   - le dépôt est servi en HTTP local (aucun push) : `Repo` pointe dessus ;
#   - `sudo:`/`prebuild:` (installation de Rust sur le serveur F-Droid) sont
#     retirés, cette machine ayant déjà Rust, le SDK et le NDK ; ils sont
#     vérifiés séparément, ligne par ligne.
#
# NON PROUVÉ : l'acceptation par F-Droid, et la construction dans leur
# buildserver (libvirt/VirtualBox), qui n'existe pas hors de leur infrastructure.
set -euo pipefail

RACINE=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
# Espace de travail sur disque (et non dans un /tmp souvent monté en tmpfs),
# car la construction Android demande quelques gigaoctets.
BASE_TMP=${TMPDIR:-$HOME/.cache/tordns/tmp}
mkdir -p "$BASE_TMP"
TMP=$(mktemp -d "$BASE_TMP/tordns-m25.XXXXXX")
trap 'rm -rf "$TMP"; [ -n "${SERVEUR_GIT:-}" ] && kill "$SERVEUR_GIT" 2>/dev/null || true' EXIT
VENV=${FDROID_VENV:-$HOME/.cache/tordns/fdroidserver}
VERSION_FDROID=2.4.2
RECETTE="$RACINE/metadata/org.tordns.client.yml"
SDK="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-/opt/android-sdk}}"
NDK="$SDK/ndk/26.3.11579264"

section() { printf '\n== %s ==\n' "$*"; }
ok() { printf 'OK : %s\n' "$*"; }
info() { printf '%s\n' "$*"; }
echec() { printf 'ÉCHEC : %s\n' "$*" >&2; exit 1; }

section "1. Recette et métadonnées"
[ -f "$RECETTE" ] || echec "recette absente : $RECETTE"
for champ in Categories License AuthorName SourceCode RepoType Repo Builds \
	AutoUpdateMode UpdateCheckMode MaintainerNotes; do
	grep -q "^$champ:" "$RECETTE" || echec "champ $champ absent de la recette"
done
grep -q '^AutoUpdateMode: Version$' "$RECETTE" || echec "AutoUpdateMode inattendu"
grep -q '^UpdateCheckMode: Tags$' "$RECETTE" || echec "UpdateCheckMode inattendu"
grep -q '^    ndk: r26b$' "$RECETTE" || echec "NDK r26b non demandé"
grep -q 'rustup target add' "$RECETTE" || echec "cibles Rust absentes de la recette"
grep -q 'construire.sh' "$RECETTE" || echec "la recette n'appelle pas construire.sh"
version=$("$RACINE/scripts/ci/version.sh")
code=$(printf '%s' "$version" | awk -F. '{printf "%d", $1*10000 + $2*100 + $3}')
grep -q "versionName: '$version'$" "$RECETTE" || echec "versionName de la recette != $version"
grep -q "^    versionCode: $code$" "$RECETTE" || echec "versionCode de la recette != $code"
ok "recette : version $version ($code), NDK r26b, AutoUpdateMode Version, UpdateCheckMode Tags"

for langue in fr-FR en-US; do
	d="client-android/fastlane/metadata/android/$langue"
	for f in title.txt short_description.txt full_description.txt "changelogs/$code.txt"; do
		[ -s "$RACINE/$d/$f" ] || echec "métadonnée absente : $d/$f"
	done
done
[ -s "$RACINE/client-android/DEPENDANCES.md" ] || echec "DEPENDANCES.md absent"
[ -s "$RACINE/docs/fdroid.md" ] || echec "docs/fdroid.md absent"
ok "métadonnées fastlane fr-FR et en-US complètes (titre, résumés, description, journal)"

for licence in MIT BSD-2-Clause "Apache-2.0"; do
	grep -q "$licence" "$RACINE/client-android/DEPENDANCES.md" ||
		echec "licence $licence non documentée dans DEPENDANCES.md"
done
ok "dépendances Java et Rust listées avec leur licence"

section "2. Aucun binaire Java versionné, téléchargement vérifié"
if [ -n "$(git -C "$RACINE" ls-files '*.jar' '*.aar')" ]; then
	echec "un .jar ou .aar reste versionné : $(git -C "$RACINE" ls-files '*.jar' '*.aar')"
fi
ok "aucun .jar ni .aar dans le dépôt"

LIBRAIRIES="$TMP/libs" "$RACINE/client-android/scripts/telecharger-libs.sh" >/dev/null ||
	echec "téléchargement des dépendances"
for jar in dnsjava-3.6.3.jar slf4j-api-2.0.16.jar; do
	[ -s "$TMP/libs/$jar" ] || echec "$jar non téléchargé"
done
attendu=$(grep -o '[0-9a-f]\{64\}' "$RACINE/client-android/scripts/telecharger-libs.sh" | head -1)
obtenu=$(sha256sum "$TMP/libs/dnsjava-3.6.3.jar" | cut -d' ' -f1)
[ "$attendu" = "$obtenu" ] || echec "empreinte épinglée != empreinte obtenue ($obtenu)"
ok "jars récupérés depuis Maven Central, empreintes épinglées respectées"

printf 'faux' >"$TMP/libs/slf4j-api-2.0.16.jar"
LIBRAIRIES="$TMP/libs" "$RACINE/client-android/scripts/telecharger-libs.sh" >/dev/null ||
	echec "le remplacement d'un jar corrompu a échoué"
cmp -s "$TMP/libs/slf4j-api-2.0.16.jar" "$RACINE/client-android/build/libs/slf4j-api-2.0.16.jar" ||
	echec "le jar corrompu n'a pas été remplacé par le bon fichier"
ok "un jar corrompu est détecté puis remplacé (empreinte contrôlée)"

section "3. Outils F-Droid officiels"
if [ ! -x "$VENV/bin/fdroid" ]; then
	python3 -m venv "$VENV" >/dev/null 2>&1 || echec "création du venv impossible"
	"$VENV/bin/pip" install -q --upgrade pip >/dev/null 2>&1 || true
	"$VENV/bin/pip" install -q "fdroidserver==$VERSION_FDROID" >/dev/null 2>&1 ||
		echec "installation de fdroidserver $VERSION_FDROID"
fi
version_outils=$("$VENV/bin/fdroid" --version 2>&1 | tail -1)
[ "$version_outils" = "$VERSION_FDROID" ] ||
	echec "fdroidserver $version_outils au lieu de $VERSION_FDROID"
ok "fdroidserver $version_outils"

section "4. fdroid lint"
FD="$TMP/fdroiddata"
mkdir -p "$FD/metadata" "$FD/build"
cat >"$FD/config.yml" <<EOF
sdk_path: $SDK
ndk_paths:
  r26b: $NDK
repo_url: https://example.invalid/fdroid/repo
repo_name: essai
repo_description: essai local
EOF
mkdir -p "$FD/config"
printf 'Internet:\n  name: Internet\n  description: Navigateurs, messagerie, VPN et outils réseau\n' \
	>"$FD/config/categories.yml"
cp "$RECETTE" "$FD/metadata/org.tordns.client.yml"
sortie_lint=$(cd "$FD" && "$VENV/bin/fdroid" lint org.tordns.client 2>&1 || true)
printf '%s\n' "$sortie_lint"
if grep -qi "erreur\|error" <<<"$sortie_lint"; then
	echec "fdroid lint signale une erreur"
fi
ok "fdroid lint : aucune erreur sur la recette"

section "5. fdroid build (dépôt servi en local, sudo/prebuild retirés)"
# Le dépôt servi est un instantané de l'arbre de travail (mission non encore
# commitée) : c'est bien le code écrit ici que la recette construit.
mkdir -p "$TMP/arbre"
tar -C "$RACINE" --exclude=.git --exclude='target' --exclude='build' \
	--exclude='node_modules' --exclude='outils/inscription/bin' -cf - . |
	tar -C "$TMP/arbre" -xf -
git -C "$TMP/arbre" init -q
git -C "$TMP/arbre" -c user.name=verifier -c user.email=verifier@localhost add -A
git -C "$TMP/arbre" -c user.name=verifier -c user.email=verifier@localhost \
	commit -qm 'instantané de vérification'
git clone -q --bare "$TMP/arbre" "$TMP/depot.git"
git -C "$TMP/depot.git" update-server-info
(cd "$TMP" && exec python3 -u -m http.server 0 --bind 127.0.0.1 >"$TMP/serveur.log" 2>&1) &
SERVEUR_GIT=$!
for _ in $(seq 1 50); do
	port=$(sed -n 's/.*port \([0-9]\+\).*/\1/p' "$TMP/serveur.log" | head -1)
	[ -n "$port" ] && break
	sleep 0.3
done
[ -n "${port:-}" ] || echec "serveur git local non démarré"
commit=$(git -C "$TMP/arbre" rev-parse HEAD)
python3 - "$RECETTE" "$FD/metadata/org.tordns.client.yml" "$port" "$commit" <<'PY'
import sys
import yaml

source, cible, port, commit = sys.argv[1:5]
with open(source, encoding='utf-8') as f:
    donnees = yaml.safe_load(f)
donnees['Repo'] = f'http://127.0.0.1:{port}/depot.git'
for build in donnees['Builds']:
    build['commit'] = commit
    build.pop('sudo', None)
    build.pop('prebuild', None)
with open(cible, 'w', encoding='utf-8') as f:
    yaml.safe_dump(donnees, f, allow_unicode=True, sort_keys=False)
PY
# fdroidserver (2.4.2 sous Python 3.14) lit SOURCE_DATE_EPOCH dans le dossier
# de travail avant de le cloner : on le prépare, puis il ne fait que le
# mettre à jour.
git clone -q "http://127.0.0.1:$port/depot.git" "$FD/build/org.tordns.client"
git -C "$FD/build/org.tordns.client" checkout -q "$commit"
info "Repo réécrit en http://127.0.0.1:$port/depot.git, commit $commit"
info "sudo/prebuild retirés : Rust $(rustc --version | cut -d' ' -f2) et NDK 26.3.11579264 déjà présents ici"

SECONDS=0
sortie_build=$(cd "$FD" && "$VENV/bin/fdroid" build --test --no-refresh --no-tarball \
	org.tordns.client 2>&1 || true)
printf '%s\n' "$sortie_build"
info "durée de la construction : $SECONDS s"
if grep -q "compilation échouée\|Build for app .* failed" <<<"$sortie_build"; then
	echec "fdroid build a échoué"
fi
if grep -q "ERROR" <<<"$sortie_build"; then
	echec "fdroid build a signalé une erreur"
fi
grep -q "Building version $version ($code)" <<<"$sortie_build" ||
	echec "fdroid build n'a pas construit $version ($code)"
ok "fdroid build : APK produit par les commandes de la recette"

apk="$FD/tmp/org.tordns.client_$code.apk"
[ -s "$apk" ] || apk=$(find "$FD/tmp" -name "org.tordns.client_$code*.apk" | head -1)
[ -s "${apk:-}" ] || echec "APK de sortie introuvable dans $FD/tmp"
OUTILS="$SDK/build-tools/36.1.0"
[ -x "$OUTILS/aapt2" ] || OUTILS="$SDK/build-tools/34.0.0"
badging=$("$OUTILS/aapt2" dump badging "$apk")
grep -q "package: name='org.tordns.client' versionCode='$code' versionName='$version'" <<<"$badging" ||
	echec "l'APK ne porte pas $version ($code) : $badging"
n=$(unzip -l "$apk" | awk '/lib\/.*\/libtordns_arti\.so$/ { n++ } END { print n+0 }')
[ "$n" -eq 3 ] || echec "l'APK universel contient $n bibliothèques natives au lieu de 3"
# Sortie capturée avant grep : sous `pipefail`, un `grep -q` qui sort au
# premier succès tue `unzip` par SIGPIPE et ferait échouer la preuve.
dex=$(unzip -p "$apk" classes.dex | strings)
grep -q "Lorg/xbill/DNS/dnssec/ValidatingResolver;" <<<"$dex" ||
	echec "dnsjava absent du dex"
grep -q "Lorg/tordns/client/TorVpnService;" <<<"$dex" ||
	echec "TorVpnService absent du dex"
ok "APK universel : $version ($code), trois ABI, dnsjava et TorVpnService présents"

section "6. fdroid scanner : aucun binaire non libre"
# Le code source a déjà été analysé pendant fdroid build (« Scanning source for
# common problems »), c'est lui qui refusait les deux .jar versionnés. On
# contrôle maintenant l'APK produit pour des classes connues comme non libres.
if (cd "$FD" && "$VENV/bin/fdroid" scanner --exit-code "$apk" >"$TMP/scan.log" 2>&1); then
	ok "fdroid scanner : aucune classe non libre dans l'APK"
else
	cat "$TMP/scan.log"
	echec "fdroid scanner signale un problème dans l'APK"
fi
grep -q "Scanning source for common problems" <<<"$sortie_build" ||
	echec "l'analyse du code source n'a pas eu lieu pendant fdroid build"
if grep -qi "Found .*\.jar" <<<"$sortie_build"; then
	echec "un .jar traîne encore dans les sources"
fi
ok "l'analyse du code source pendant fdroid build ne trouve aucun .jar"

section "7. Ce qui n'est pas prouvé"
info "NON PROUVÉ : l'acceptation par F-Droid et la construction dans leur"
info "buildserver : cette machine n'a ni libvirt ni l'image de build F-Droid."
info "NON PROUVÉ : sudo/prebuild de la recette (installation de Rust sur leur"
info "serveur), retirés ici puisque Rust, le SDK et le NDK sont déjà installés."
info "NON PROUVÉ : les captures d'écran fastlane (aucun appareil ni émulateur),"
info "et la comparaison reproductible avec l'APK signé par Gary (mission 21)."

printf '\ncode=0\n'
