#!/bin/sh
# TorDNS — date de référence des archives et binaires.
# $SOURCE_DATE_EPOCH est prioritaire ; sinon la date du commit courant.
set -eu
RACINE=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
if [ -n "${SOURCE_DATE_EPOCH:-}" ]; then
	printf '%s\n' "$SOURCE_DATE_EPOCH"
	exit 0
fi
git -C "$RACINE" log -1 --format=%ct 2>/dev/null || printf '0\n'
