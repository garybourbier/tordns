#!/usr/bin/env bash
# TorDNS — lint commun local/CI : actionlint, shellcheck, gofmt, go vet,
# cargo fmt, et épinglage des actions par empreinte de commit.
set -euo pipefail

RACINE=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
OUTILS=${TORDNS_OUTILS:-${XDG_CACHE_HOME:-$HOME/.cache}/tordns-ci}
mkdir -p "$OUTILS"

section() { printf '\n== %s ==\n' "$*"; }
echec() { printf 'ÉCHEC : %s\n' "$*" >&2; exit 1; }

installer_actionlint() {
	[ "$(uname -s)" = Linux ] && [ "$(uname -m)" = x86_64 ] || {
		echec "actionlint absent et installation automatique limitée à Linux x86_64"
	}
	local archive="$OUTILS/actionlint.tar.gz"
	curl -fsSL --max-time 120 \
		https://github.com/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_linux_amd64.tar.gz \
		-o "$archive"
	echo "8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8  $archive" |
		sha256sum -c - >/dev/null || echec "somme d'actionlint invalide"
	tar -xzf "$archive" -C "$OUTILS" actionlint
	rm -f "$archive"
}

installer_shellcheck() {
	[ "$(uname -s)" = Linux ] && [ "$(uname -m)" = x86_64 ] || {
		echec "shellcheck absent et installation automatique limitée à Linux x86_64"
	}
	local archive="$OUTILS/shellcheck.tar.xz"
	curl -fsSL --max-time 120 \
		https://github.com/koalaman/shellcheck/releases/download/v0.11.0/shellcheck-v0.11.0.linux.x86_64.tar.xz \
		-o "$archive"
	echo "8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198  $archive" |
		sha256sum -c - >/dev/null || echec "somme de shellcheck invalide"
	tar -xJf "$archive" -C "$OUTILS"
	mv "$OUTILS/shellcheck-v0.11.0/shellcheck" "$OUTILS/shellcheck"
	rm -rf "$OUTILS/shellcheck-v0.11.0" "$archive"
}

ACTIONLINT=$(command -v actionlint || true)
if [ -z "$ACTIONLINT" ]; then
	installer_actionlint
	ACTIONLINT="$OUTILS/actionlint"
fi
SHELLCHECK=$(command -v shellcheck || true)
if [ -z "$SHELLCHECK" ]; then
	installer_shellcheck
	SHELLCHECK="$OUTILS/shellcheck"
fi

section "1. Workflows : empreintes et actionlint"
while IFS= read -r ligne; do
	ref=${ligne#*@}
	ref=${ref%%[[:space:]]*}
	if ! printf '%s' "$ref" | grep -Eq '^[0-9a-f]{40}$'; then
		echec "action non épinglée par empreinte : $ligne"
	fi
	case "$ligne" in
		*\#*) ;;
		*) echec "action sans commentaire de version : $ligne" ;;
	esac
done < <(grep -RhE '^[[:space:]]*uses:[[:space:]]*[^[:space:]#]+' "$RACINE/.github/workflows" 2>/dev/null || true)
if grep -Rq 'pull_request_target' "$RACINE/.github" 2>/dev/null; then
	echec "pull_request_target interdit"
fi
"$ACTIONLINT" "$RACINE"/.github/workflows/*.yml

section "2. shellcheck"
find "$RACINE" -type f -name '*.sh' \
	-not -path '*/.git/*' -not -path '*/target/*' -not -path '*/build/*' -print0 |
	sort -z | xargs -0 "$SHELLCHECK" -x

section "3. gofmt et go vet"
NON_FORMATES=$(find "$RACINE" -type f -name '*.go' -not -path '*/.git/*' -not -path '*/vendor/*' -print0 |
	xargs -0 gofmt -l)
[ -z "$NON_FORMATES" ] || echec "fichiers Go non formatés : $NON_FORMATES"
while IFS= read -r module; do
	(cd "$(dirname "$module")" && go vet ./...)
done < <(find "$RACINE" -name go.mod -not -path '*/.git/*' | sort)

section "4. cargo fmt"
while IFS= read -r manifeste; do
	(cd "$(dirname "$manifeste")" && cargo fmt -- --check)
done < <(find "$RACINE" -name Cargo.toml -not -path '*/target/*' | sort)

section "Bilan"
echo "code=0"
