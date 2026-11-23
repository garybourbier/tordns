#!/usr/bin/env bash
# TorDNS — fuzzing local ou CI des entrées réseau.
#   scripts/ci/fuzz.sh 2m                    # toutes les cibles Go
#   scripts/ci/fuzz.sh 10m FuzzRelaisClient  # une cible
#   scripts/ci/fuzz.sh 10m rust-dns
# Le corpus généré va dans dist/fuzz-corpus (ignoré par git, joint en CI).
set -euo pipefail

RACINE=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
DUREE=${1:-2m}
CIBLE=${2:-toutes}
mkdir -p "$RACINE/dist/fuzz-corpus"

secondes() {
	case $1 in
	*[0-9]m) echo $((${1%m} * 60)) ;;
	*[0-9]s) echo "${1%s}" ;;
	*[0-9]) echo "$1" ;;
	*) echo 120 ;;
	esac
}

paquet_go() {
	case $1 in
	FuzzPasserelleDoH) echo "serveur/passerelle" ;;
	FuzzRelaisClient | FuzzValiderDNSSEC) echo "client-linux/relais" ;;
	FuzzEnTeteProxy) echo "controleur/registre" ;;
	FuzzManifeste) echo "outils/manifeste" ;;
	*) return 1 ;;
	esac
}

lancer_go() {
	cible=$1
	paquet=$(paquet_go "$cible") || { echo "ERREUR : cible Go inconnue : $cible" >&2; return 1; }
	echo "== Go $cible ($paquet, $DUREE)"
	(cd "$RACINE/$paquet" && go test -run='^$' -fuzz="^$cible$" -fuzztime="$DUREE" \
		-parallel=1 -test.fuzzcachedir="$RACINE/dist/fuzz-corpus/$cible")
}

lancer_rust() {
	cible=$1
	if ! command -v cargo-fuzz >/dev/null 2>&1; then
		echo "NON PROUVÉ : cargo-fuzz absent, cible Rust $cible non exécutée."
		return 0
	fi
	if ! rustup toolchain list 2>/dev/null | grep -q '^nightly'; then
		echo "NON PROUVÉ : toolchain nightly absente, cible Rust $cible non exécutée."
		return 0
	fi
	sec=$(secondes "$DUREE")
	case $cible in
	rust-dns)
		echo "== Rust dns ($sec s)"
		(cd "$RACINE/client-windows" && cargo +nightly fuzz run dns -- -max_total_time="$sec")
		;;
	rust-manifeste)
		echo "== Rust manifeste ($sec s)"
		(cd "$RACINE/outils/manifeste-rust" && cargo +nightly fuzz run verifier -- -max_total_time="$sec")
		;;
	*) echo "ERREUR : cible Rust inconnue : $cible" >&2; return 1 ;;
	esac
}

case $CIBLE in
toutes)
	for cible in FuzzPasserelleDoH FuzzRelaisClient FuzzValiderDNSSEC FuzzEnTeteProxy FuzzManifeste; do
		lancer_go "$cible"
	done
	for cible in rust-dns rust-manifeste; do
		lancer_rust "$cible"
	done
	;;
rust-*) lancer_rust "$CIBLE" ;;
*) lancer_go "$CIBLE" ;;
esac
echo "code=0"
