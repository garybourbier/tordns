# Journal des versions de TorDNS

Les notes de release sont extraites de la section correspondant au tag
(`vX.Y.Z`). La section doit exister avant de pousser le tag.

## 0.8.0 — 2026-11-23

- Client Linux amd64/arm64/armv7 (archive, `.deb`), client Windows
  x86_64/aarch64, APK Android des trois ABI, client macOS Intel et Apple
  Silicon avec `.pkg`.
- Images du nœud et du contrôleur publiées en multi-arch sur GHCR, épinglées
  par empreinte dans `images.txt`.
- Publication : `SHA256SUMS`, attestations de provenance, release brouillon ;
  Gary signe les APK, construit et signe le manifeste, puis publie.
