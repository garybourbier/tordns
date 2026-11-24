#!/usr/bin/env bash
# Preuves exécutables de la mission 26 (client iOS).
#
# Ce qui est prouvable sur Linux l'est : le crate Tor partagé, le pont C, son
# export de symboles, la non-régression Android, la cohérence des fichiers
# Apple et du YAML. La compilation Swift, le projet Xcode et le job macOS ne
# peuvent pas l'être : chaque point est écrit NON PROUVÉ, jamais coché.
set -euo pipefail

RACINE=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$RACINE"
echec() { echo "ÉCHEC : $*" >&2; exit 1; }
ok() { echo "OK : $*"; }
section() { printf '\n== %s ==\n' "$*"; }

IOS=client-ios
PARTAGE=outils/arti-rust

section "1. Client iOS : fichiers livrés"
for f in "$IOS/project.yml" "$IOS/README.md" "$IOS/rust/Cargo.toml" \
	"$IOS/rust/src/lib.rs" "$IOS/rust/include/tordns.h" \
	"$IOS/Config/Info.plist" "$IOS/Config/Info-extension.plist" \
	"$IOS/Config/TorDNS.entitlements" "$IOS/Config/Extension.entitlements" \
	"$IOS/Config/TorDNS-Bridging-Header.h" "$IOS/Config/ExportOptions.plist" \
	"$IOS/scripts/construire-rust.sh" scripts/ci/client-ios.sh; do
	[ -s "$f" ] || echec "fichier absent ou vide : $f"
done
[ -x "$IOS/scripts/construire-rust.sh" ] || echec "construire-rust.sh non exécutable"
[ -x scripts/ci/client-ios.sh ] || echec "scripts/ci/client-ios.sh non exécutable"
for f in "$IOS"/Sources/App/*.swift "$IOS"/Sources/Partage/*.swift \
	"$IOS"/Sources/Extension/*.swift "$IOS"/Tests/*.swift; do
	[ -s "$f" ] || echec "source Swift absente ou vide : $f"
done
if find "$IOS" -name '*.xcodeproj' -o -name '*.xcworkspace' | grep -q .; then
	echec "un projet Xcode est versionné ; seul project.yml doit l'être"
fi
bash -n "$IOS/scripts/construire-rust.sh" || echec "construire-rust.sh : syntaxe"
bash -n scripts/ci/client-ios.sh || echec "client-ios.sh : syntaxe"
ok "$(find "$IOS" -name '*.swift' | wc -l) fichiers Swift, aucun .xcodeproj, scripts actionnables"

section "2. Une seule implémentation Tor/DoH, partagée"
grep -rq 'POST /dns-query' "$PARTAGE/src" ||
	echec "le crate partagé ne porte pas la requête DoH"
if grep -rl 'POST /dns-query' --include='*.rs' client-android client-ios |
	grep -v '^client-android/target' | grep -q .; then
	echec "la requête DoH est dupliquée hors du crate partagé"
fi
for crate in client-android/rust "$IOS/rust"; do
	grep -q 'tordns-tor *= *{ *path *= *"../../outils/arti-rust"' "$crate/Cargo.toml" ||
		echec "$crate ne dépend pas du crate partagé"
done
if grep -qE '^(arti-client|tor-rtcompat|futures|rustls|tokio) *=' client-android/rust/Cargo.toml; then
	echec "Android déclare encore les dépendances Tor : la logique est dupliquée"
fi
if grep -rq 'TorClientConfigBuilder' --include='*.rs' client-android client-ios |
	grep -v 'target/' | grep -q .; then
	echec "un adaptateur construit encore son propre client Tor"
fi
ok "Android et iOS délèguent au crate $PARTAGE (aucune copie)"

section "3. Tests hôte des deux crates"
# La sortie est capturée avant filtrage : `cargo test | grep -q` tue cargo par
# SIGPIPE et ferait échouer la preuve avec pipefail.
(cd "$PARTAGE" && cargo test --locked --quiet) >/tmp/verifier-m26-partage.log 2>&1 ||
	{ tail -20 /tmp/verifier-m26-partage.log >&2; echec "tests du crate partagé rouges"; }
(cd "$IOS/rust" && cargo test --locked --quiet) >/tmp/verifier-m26-pont.log 2>&1 ||
	{ tail -20 /tmp/verifier-m26-pont.log >&2; echec "tests du pont C rouges"; }
PARTAGE_OK=$(grep -c 'test result: ok' /tmp/verifier-m26-partage.log || true)
PONT_OK=$(grep -c 'test result: ok' /tmp/verifier-m26-pont.log || true)
[ "$PARTAGE_OK" -ge 1 ] || echec "crate partagé : aucun « test result: ok »"
[ "$PONT_OK" -ge 1 ] || echec "pont C : aucun « test result: ok »"
grep -q '6 passed' /tmp/verifier-m26-partage.log ||
	echec "crate partagé : moins de 6 tests exécutés"
grep -q '6 passed' /tmp/verifier-m26-pont.log ||
	echec "pont C : moins de 6 tests exécutés"
ok "crate partagé et pont C : 6 + 6 tests verts (Tor, DoH, manifeste, ABI)"

section "4. ABI C : exportée par le binaire, déclarée dans l'en-tête"
(cd "$IOS/rust" && cargo build --locked --release --lib >/dev/null 2>&1) ||
	echec "bibliothèque statique iOS impossible à construire pour l'hôte"
BIB="$IOS/rust/target/release/libtordns_ios.a"
[ -s "$BIB" ] || echec "libtordns_ios.a absente"
python3 - "$RACINE" "$BIB" "$IOS/rust/include/tordns.h" <<'PY'
import pathlib
import re
import subprocess
import sys

racine, bibliotheque, entete = sys.argv[1:]
source = (pathlib.Path(racine) / "client-ios/rust/src/lib.rs").read_text()
exportees = set(re.findall(r'pub extern "C" fn (\w+)', source))
declarees = set(re.findall(r'\b(\w+)\(', pathlib.Path(entete).read_text()))
declarees = {n for n in declarees if n.startswith("tordns_")}
if not exportees:
    raise SystemExit("aucune fonction extern « C » dans le crate iOS")
absentes = sorted(exportees - declarees)
if absentes:
    raise SystemExit(f"fonctions Rust non déclarées dans tordns.h : {absentes}")
inutilisees = sorted(declarees - exportees)
if inutilisees:
    raise SystemExit(f"en-tête déclare des fonctions absentes du crate : {inutilisees}")

sortie = subprocess.run(["nm", "-g", "--defined-only", bibliotheque],
                        capture_output=True, text=True, check=True).stdout
symboles = set(re.findall(r"\bT (_?tordns_\w+)", sortie))
manquants = sorted(f"_{n}" if f"_{n}" not in symboles else n
                   for n in exportees if n not in symboles and f"_{n}" not in symboles)
if manquants:
    raise SystemExit(f"symboles absents de libtordns_ios.a : {manquants}")
print(f"OK : {len(exportees)} fonctions C exportées et liées dans libtordns_ios.a")
PY

section "5. Coque Apple : plists, entitements, projet Xcode"
python3 - "$RACINE/client-ios" <<'PY'
import pathlib
import plistlib
import sys

client = pathlib.Path(sys.argv[1])
attendus = {
    "Config/Info.plist": ["CFBundleShortVersionString", "CFBundleVersion"],
    "Config/Info-extension.plist": ["NSExtension"],
}
for nom, cles in attendus.items():
    with (client / nom).open("rb") as f:
        contenu = plistlib.load(f)
    for cle in cles:
        if cle not in contenu:
            raise SystemExit(f"{nom} : clé {cle} absente")
extension = plistlib.load((client / "Config/Info-extension.plist").open("rb"))["NSExtension"]
if extension.get("NSExtensionPointIdentifier") != "com.apple.networkextension.packet-tunnel":
    raise SystemExit("l'extension n'est pas un tunnel de paquets")
if not extension.get("NSExtensionPrincipalClass", "").endswith("FournisseurTunnel"):
    raise SystemExit("classe principale de l'extension absente du plist")
for nom in ("Config/TorDNS.entitlements", "Config/Extension.entitlements"):
    droits = plistlib.load((client / nom).open("rb"))
    capacites = droits.get("com.apple.developer.networking.networkextension", [])
    if "packet-tunnel-provider" not in capacites:
        raise SystemExit(f"{nom} : packet-tunnel-provider absent")
    if "dns-proxy" in capacites:
        raise SystemExit(f"{nom} : dns-proxy demandé, réservé aux appareils supervisés")
    if "group.org.tordns.client" not in droits.get("com.apple.security.application-groups", []):
        raise SystemExit(f"{nom} : groupe d'applications absent")
plistlib.load((client / "Config/ExportOptions.plist").open("rb"))
print("OK : plists lisibles, tunnel de paquets, entitements cohérents")
PY
python3 - "$RACINE/client-ios" <<'PY'
import pathlib
import re
import sys

client = pathlib.Path(sys.argv[1])
projet = (client / "project.yml").read_text()
for attendu in ("TorDNS:", "TorDNSTunnel:", "TorDNSTests:", "xcodegen",
                "NEDNSProxyProvider", "packet-tunnel-provider"):
    if attendu not in projet:
        raise SystemExit(f"project.yml : « {attendu} » absent")
if "build/rust/$(PLATFORM_NAME)" not in projet:
    raise SystemExit("project.yml : chemin de la bibliothèque Rust incohérent")
script = (client / "scripts/construire-rust.sh").read_text()
if 'SORTIE="$ICI/build/rust/$PLATEFORME"' not in script:
    raise SystemExit("construire-rust.sh n'écrit pas là où project.yml cherche")
magasin = (client / "Sources/Partage/Magasin.swift").read_text()
groupe = re.search(r'static let groupe = "([^"]+)"', magasin).group(1)
if groupe not in (client / "Config/TorDNS.entitlements").read_text():
    raise SystemExit("le groupe d'applications de Magasin.swift n'est pas dans les entitements")
for symbole in re.findall(r'\btordns_\w+', (client / "Sources/Partage/PontTor.swift").read_text()):
    pass
print(f"OK : trois cibles xcodegen, chemins Rust cohérents, groupe {groupe} partagé")
PY
if command -v python3 >/dev/null; then
	python3 - "$RACINE/client-ios/project.yml" <<'PY' || echec "project.yml : YAML invalide"
import sys
import yaml

with open(sys.argv[1]) as f:
    config = yaml.safe_load(f)
if set(config.get("targets", {})) != {"TorDNS", "TorDNSTunnel", "TorDNSTests"}:
    raise SystemExit("cibles inattendues dans project.yml")
PY
fi
ok "project.yml et scripts Apple cohérents"

section "6. Swift n'appelle que l'ABI déclarée"
python3 - "$RACINE/client-ios" <<'PY'
import pathlib
import re
import sys

client = pathlib.Path(sys.argv[1])
entete = (client / "rust/include/tordns.h").read_text()
declarees = set(re.findall(r'\b(tordns_\w+)\(', entete))
utilisees = set()
for fichier in client.glob("Sources/**/*.swift"):
    utilisees |= set(re.findall(r'\b(tordns_\w+)\(', fichier.read_text()))
inconnues = sorted(utilisees - declarees)
if inconnues:
    raise SystemExit(f"Swift appelle des fonctions absentes de tordns.h : {inconnues}")
if not utilisees:
    raise SystemExit("aucune fonction de l'ABI C appelée depuis Swift")
print(f"OK : {len(utilisees)} fonctions C appelées depuis Swift, toutes déclarées")
PY
grep -q 'tordns.h' client-ios/Config/TorDNS-Bridging-Header.h ||
	echec "l'en-tête de pont n'inclut pas tordns.h"
ok "en-tête de pont en place"

section "7. Choix Apple documenté et cohérent"
grep -q 'NEDNSProxyProvider' client-ios/README.md ||
	echec "README : le mécanisme écarté n'est pas expliqué"
grep -qi 'supervis' client-ios/README.md ||
	echec "README : la raison du refus du proxy DNS n'est pas donnée"
grep -q 'TN3134' client-ios/README.md ||
	echec "README : référence Apple absente"
grep -q 'matchDomains' client-ios/Sources/Extension/FournisseurTunnel.swift ||
	echec "l'extension ne limite pas la capture au DNS"
grep -q 'includedRoutes = \[\]' client-ios/Sources/Extension/FournisseurTunnel.swift ||
	echec "l'extension inclurait des routes : tout le trafic passerait par le tunnel"
grep -q '^## Ce qui reste à prouver' client-ios/README.md ||
	echec "README : liste des preuves manquantes absente"
ok "tunnel limité au DNS, choix argumenté, limites écrites"

section "8. Non-régression Android (le crate partagé compile pour Android)"
ABIS=arm64-v8a UNIVERSEL=non ./client-android/scripts/construire.sh >/tmp/verifier-m26-android.log 2>&1 ||
	{ tail -20 /tmp/verifier-m26-android.log >&2; echec "construction Android cassée par l'extraction"; }
SO=$(ls client-android/build/apk/lib/arm64-v8a/libtordns_arti.so 2>/dev/null ||
	ls client-android/build/lib/arm64-v8a/libtordns_arti.so 2>/dev/null || true)
[ -n "$SO" ] || echec "libtordns_arti.so introuvable après construction"
# `nm | grep -q` tue nm par SIGPIPE et ferait échouer la preuve avec pipefail.
SYMBOLES=$(nm -D "$SO")
for symbole in Java_org_tordns_client_Arti_demarrer Java_org_tordns_client_Arti_doh \
	Java_org_tordns_client_Arti_verifierManifeste Java_org_tordns_client_Arti_telecharger; do
	grep -q " T $symbole$" <<<"$SYMBOLES" || echec "symbole JNI absent de $SO : $symbole"
done
ok "APK arm64 construit, quatre symboles JNI exportés ($(du -h "$SO" | cut -f1))"

section "9. CI : job macOS et scripts"
# Même cache d'outils que scripts/ci/lint.sh (binaire épinglé par SHA-256).
OUTILS=${TORDNS_OUTILS:-${XDG_CACHE_HOME:-$HOME/.cache}/tordns-ci}
ACTIONLINT=$(command -v actionlint || true)
[ -n "$ACTIONLINT" ] || ACTIONLINT=$OUTILS/actionlint
[ -x "$ACTIONLINT" ] || echec "actionlint introuvable (lancer scripts/ci/lint.sh)"
"$ACTIONLINT" .github/workflows/ci.yml || echec "actionlint : ci.yml invalide"
python3 - "$RACINE/.github/workflows/ci.yml" <<'PY'
import sys
import yaml

with open(sys.argv[1]) as f:
    flux = yaml.safe_load(f)
tache = flux["jobs"].get("ios")
if not tache:
    raise SystemExit("job ios absent de ci.yml")
if tache["runs-on"] != "macos-latest":
    raise SystemExit(f"job ios sur {tache['runs-on']}, attendu macos-latest")
etapes = " ".join(str(e.get("run", "")) for e in tache["steps"])
if "scripts/ci/client-ios.sh" not in etapes:
    raise SystemExit("le job ios n'appelle pas scripts/ci/client-ios.sh")
secrets = {k for k in tache.get("env", {})}
if "TORDNS_TEAM_ID" not in secrets:
    raise SystemExit("le job ios ne lit pas les secrets Apple en env")
print("OK : job ios sur macos-latest, script du dépôt, secrets facultatifs")
PY
ok "actionlint vert sur ci.yml, job ios conforme aux règles"

section "10. Aucun secret, aucune adresse .onion réelle"
# -I : les binaires de target/ ne sont pas du texte ; --exclude-dir : jamais
# les artefacts de compilation, qui contiennent les mêmes octets que les rlibs.
SOURCES_IOS=(client-ios --exclude-dir=target --exclude-dir=build --exclude-dir=.build)
if grep -RInE '(BEGIN [A-Z ]*PRIVATE KEY|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})' \
	"${SOURCES_IOS[@]}" scripts/ci/client-ios.sh; then
	echec "secret détecté dans le client iOS"
fi
if grep -RInE '\b[a-z2-7]{52,56}\.onion\b' "${SOURCES_IOS[@]}" scripts/ci/client-ios.sh; then
	echec "adresse .onion réelle détectée"
fi
ok "aucune clé, aucune adresse .onion complète"

section "11. Ce qui ne peut pas être prouvé ici"
if command -v xcrun >/dev/null || command -v xcodebuild >/dev/null; then
	ok "chaîne Apple présente : relancer ce vérificateur sous macOS"
else
	echo "NON PROUVÉ : compilation Swift, projet xcodegen, extension, tests simulateur."
	echo "NON PROUVÉ : archive signée, envoi TestFlight, exécution du job macOS."
	echo "NON PROUVÉ : mémoire d'Arti dans l'extension (limite iOS ≈ 50 Mo)."
	echo "NON PROUVÉ : activation du tunnel sur un appareil réel."
fi
if rustup target list --installed 2>/dev/null | grep -qx aarch64-apple-ios; then
	if (cd "$IOS/rust" && cargo check --locked --target aarch64-apple-ios --lib >/tmp/verifier-m26-ios.log 2>&1); then
		ok "cargo check --target aarch64-apple-ios passe"
	else
		grep -q 'xcrun' /tmp/verifier-m26-ios.log ||
			echec "échec iOS inattendu (ni xcrun ni SDK Apple en cause)"
		echo "NON PROUVÉ : la cible aarch64-apple-ios est installée, mais une dépendance"
		echo "            (ring, C) exige xcrun et le SDK iOS : compilation impossible ici."
	fi
else
	echo "NON PROUVÉ : cible aarch64-apple-ios non installée (rustup target add)."
fi

echo
echo "code=0"
