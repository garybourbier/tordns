#!/bin/sh
# TorDNS — version injectée dans les binaires.
# Priorité : $VERSION, puis le tag exact du commit, puis noeud/VERSION.
set -eu
RACINE=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
if [ -n "${VERSION:-}" ]; then
	printf '%s\n' "$VERSION"
	exit 0
fi
if tag=$(git -C "$RACINE" describe --tags --exact-match 2>/dev/null); then
	printf '%s\n' "${tag#v}"
	exit 0
fi
tr -d '[:space:]' <"$RACINE/noeud/VERSION"
