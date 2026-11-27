# Checklist de publication — 0.8.0

Préparée le 27/11/2026, avant tout tag. La publication elle-même est un acte de
Gary : ce document liste ce qui a été exécuté ici, ce qui reste à faire, et ce
qui n'a pas pu être prouvé.

État du dépôt : `master`, `noeud/VERSION` = `0.8.0`, section `## 0.8.0` présente
dans `CHANGELOG.md`, aucun tag posé.

## 1. Vérifications exécutées sur cette machine (27/11/2026)

| Contrôle | Commande | Résultat |
|---|---|---|
| Lint complet (actionlint 1.7.12, shellcheck 0.11.0, gofmt, `go vet` de tous les modules, `cargo fmt --check`) | `scripts/ci/lint.sh` | vert, code 0 |
| Tag cohérent avec la version | `scripts/ci/verifier-version-tag.sh v0.8.0` | vert |
| Notes de release extraites du CHANGELOG | `scripts/ci/notes-release.sh v0.8.0` | texte non vide |
| Assemblage de release, sommes, attestations (local) | `scripts/verifier-m16.sh` | vert, code 0 |
| Recette F-Droid, métadonnées, `fdroid lint`, build local | `scripts/verifier-m25.sh` | vert, code 0 |
| DNSSEC, registre, vecteurs communs, rejeu de m10/m11/m12/m19 | `scripts/verifier-m28.sh` | vert, code 0 |
| Client Linux, Android, Windows | `go test ./...`, `client-android/scripts/tester.sh`, `cargo test --locked` | verts |

Deux vérificateurs de publication sont **bloqués par un outil absent** :

- `scripts/verifier-m14.sh` et `scripts/verifier-m21.sh` échouent sur
  « makensis absent (paquet nsis requis) ». Tout le reste de leurs étapes passe
  (compilations, binaires, sommes, reproductibilité Linux) ; seule la
  fabrication de l'installateur NSIS Windows manque. Le paquet `nsis` n'existe
  pas dans les dépôts de cette machine et son installation demande root.

NON EXÉCUTÉ ici : la suite complète `verifier-m07.sh` … `verifier-m27.sh`
(QEMU, images Docker, carte Raspberry Pi, matériel réel), le premier passage
GitHub Actions, la signature APK, la notarisation Apple, les attestations
réelles et les images GHCR. Ces preuves ne peuvent être obtenues qu'au premier
push.

## 2. À faire par Gary, dans cet ordre

1. Pousser `master`.
2. Poser le tag `v0.8.0` (le workflow release refuse un tag qui ne correspond
   pas à `noeud/VERSION`).
3. Contrôler la release brouillon : un fichier par cible de
   `site/telechargements.json`, `SHA256SUMS`, attestations de provenance,
   `images.txt` épinglé par empreinte, images GHCR multi-arch.
4. Télécharger les APK et l'installateur Windows de la release brouillon,
   les signer chez soi, construire et signer le manifeste (`outils/`), puis
   publier. La CI ne signe jamais avec la clé de Gary.
5. Activer GitHub Pages (source « GitHub Actions ») et vérifier l'URL publiée.
6. Rejouer `scripts/verifier-m14.sh` et `scripts/verifier-m21.sh` sur une
   machine avec `makensis`, ou accepter que l'installateur Windows soit
   vérifié seulement au premier passage CI.

## 3. Après publication

- Vérifier un téléchargement de bout en bout :
  `sha256sum -c SHA256SUMS` et `gh attestation verify <fichier> -R garybourbier/tordns`.
- Ouvrir la demande F-Droid : `UpdateCheckMode: Tags` attend `v0.8.0`.
- Renseigner la date et le commit (`git rev-parse HEAD`) dans
  `docs/securite/demande-otf.md` avant dépôt.

Le détail des limites par produit reste dans `docs/missions/journal.md` et
`docs/a-faire-gary.md`.
