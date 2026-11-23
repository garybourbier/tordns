# Reconstruire une version publiée

Cette procédure vérifie que les binaires d'une release proviennent bien du code
public. Elle n'utilise ni clé de signature ni dépôt privé.

## Linux amd64

```sh
gh release download v0.8.0 --repo garybourbier/tordns --dir /hors/depot/v0.8.0
./scripts/ci/reproduire.sh v0.8.0 --sommes /hors/depot/v0.8.0/SHA256SUMS
```

Le script extrait le tag par `git archive`, monte cette copie en lecture seule
dans l'image `golang:1.23-bookworm` épinglée par empreinte, impose
`SOURCE_DATE_EPOCH` à la date du commit et construit l'archive et le `.deb`
amd64. Il compare ensuite chaque SHA-256 reconstruit à `SHA256SUMS`. Un écart
est affiché avec le fichier concerné ; `code=0` signifie que tous les fichiers
Linux amd64 reconstruits figurent dans les sommes publiées.

## Windows x86_64

La chaîne est épinglée par `client-windows/rust-toolchain.toml` et
`Cargo.lock` (`cargo build --locked`). Le chemin absolu est retiré par
`--remap-path-prefix`, le PE est horodaté avec `SOURCE_DATE_EPOCH` et
l'installateur NSIS est post-traité par `scripts/ci/pe-timestamp.py` :

```sh
rustup target add x86_64-pc-windows-gnu
VERSION=0.8.0 SOURCE_DATE_EPOCH=$(git log -1 --format=%ct v0.8.0) \
  DIST=/tmp/tordns-win ./scripts/ci/client-windows.sh x86_64
sha256sum /tmp/tordns-win/*
```

Comparer avec les mêmes noms dans la release. Le timestamp PE et le chemin de
compilation sont fixés ; le contenu de `wintun.dll` est épinglé par SHA-256.

## Android

`client-android/scripts/assembler.py` trie les entrées du ZIP et remplace
toutes les dates par `SOURCE_DATE_EPOCH` ; les APK `-NON-SIGNE-POUR-PUBLICATION`
sont alignés mais **non signés**. La signature de Gary est ajoutée après la
release et ne fait pas partie de la comparaison :

```sh
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct v0.8.0) \
  ./scripts/ci/client-android.sh
sha256sum dist/client-android/*-NON-SIGNE-POUR-PUBLICATION.apk
```

Les outils `aapt2`, `d8`, `zipalign` et `apksigner` viennent du build-tools
Android épinglé par la CI (36.1.0).

## macOS et images Docker

macOS n'est pas reconstruit par `scripts/ci/reproduire.sh` : `pkgbuild`,
`lipo` et la signature Developer ID exigent un hôte macOS. Les images
multi-arch sont construites par `scripts/ci/images-release.sh` avec des bases
épinglées par empreinte et `SOURCE_DATE_EPOCH` ; Buildx doit supporter
`--rewrite-timestamp`, sinon le script l'annonce et les images restent non
reproductibles.

## Ce qui reste non déterministe

- Le timestamp PE de l'installateur NSIS est normalisé après coup ; le
  désinstalleur généré à l'installation peut varier.
- Les images Docker dépendent de la version de Buildx et du support de
  `--rewrite-timestamp`.
- macOS, la signature Developer ID et la notarisation ne sont pas couvertes
  localement.
- La signature APK de publication n'est pas dans l'APK non signé comparé.
