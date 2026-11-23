# Mission 21 — Compilations reproductibles

But : n'importe qui peut recompiler une version publiée et obtenir **les mêmes octets**, ce
qui prouve que les fichiers de la release viennent bien du code source public.

## À livrer

- Client Linux et macOS (Go) : `-trimpath`, `-buildvcs=false` ou VCS fixé, `-ldflags
  "-buildid="`, version injectée depuis le tag, chaîne Go épinglée (`toolchain` dans
  `go.mod`), `SOURCE_DATE_EPOCH` = date du commit pour les archives (`tar --sort=name
  --mtime --owner=0 --group=0 --numeric-owner`, `gzip -n`), `.deb` déterministe.
- Windows (Rust) : chaîne Rust épinglée (`rust-toolchain.toml`), `--remap-path-prefix`,
  `Cargo.lock` utilisé (`--locked`), NSIS avec date fixée ; documenter ce qui reste non
  déterministe s'il y en a (horodatage PE : le mettre à zéro ou à `SOURCE_DATE_EPOCH`).
- Android : APK non signé reproductible (ordre des entrées, dates du zip, `d8`/`aapt2`
  épinglés) ; la signature de Gary s'ajoute ensuite et ne fait pas partie de la comparaison.
- Images Docker : bases épinglées par empreinte, `SOURCE_DATE_EPOCH`, `rewrite-timestamp`
  de buildx.
- `scripts/ci/reproduire.sh vX.Y.Z` : reconstruit depuis le tag dans un conteneur propre et
  compare au `SHA256SUMS` de la release ; `docs/reproduire.md` pour le public.

## Preuve (`scripts/verifier-m21.sh`)

Deux constructions successives dans deux dossiers différents (et deux conteneurs propres)
donnent des SHA-256 identiques pour chaque fichier Linux, Windows x86_64 et l'APK non
signé ; chaque écart restant est listé avec sa cause. NON PROUVÉ attendu : macOS et images
multi-arch (CI).
