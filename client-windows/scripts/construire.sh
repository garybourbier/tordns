#!/usr/bin/env bash
# Construit le client Windows depuis Linux (MinGW) et, si makensis est présent,
# l'installateur. Aucune étape ne nécessite Windows.
set -euo pipefail
RACINE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CIBLE="x86_64-pc-windows-gnu"

echo "== 1. Tests portables =="
(cd "$RACINE" && cargo test --locked)

echo "== 2. Binaire Windows ($CIBLE) =="
RACINE_ABS=$RACINE
(cd "$RACINE" && \
    RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$RACINE_ABS=. -C debuginfo=0 -C link-arg=-Wl,--no-insert-timestamp" \
    cargo build --release --locked --target "$CIBLE")
mkdir -p "$RACINE/dist"
cp "$RACINE/target/$CIBLE/release/tordns-client.exe" "$RACINE/dist/"

# WinTun n'est pas distribué avec ce dépôt : copier wintun.dll dans dist/ si
# vous l'avez téléchargée depuis la source officielle.
if [ -f "$RACINE/dist/wintun.dll" ]; then
    echo "wintun.dll présente : elle sera incluse par l'installateur."
else
    echo "AVERTISSEMENT : dist/wintun.dll absente (pilote requis à l'exécution)."
fi

echo "== 3. Installateur NSIS (optionnel) =="
if command -v makensis >/dev/null 2>&1; then
    (cd "$RACINE/installateur" && makensis tordns.nsi)
    ls -l "$RACINE/installateur"/*.exe
else
    echo "makensis absent : installateur non généré (script fourni)."
fi

echo "Binaire : $RACINE/dist/tordns-client.exe"
