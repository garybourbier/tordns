# Publier une version de TorDNS

Gary est le seul à pousser un tag et à publier une release. Aucune clé privée
ne doit se trouver dans le dépôt, dans un workflow ou dans `dist/`.

## 1. Préparer la version

1. Mettre à jour `noeud/VERSION` (`X.Y.Z`, sans `v`).
2. Ajouter une section `## X.Y.Z — AAAA-MM-JJ` en tête de `CHANGELOG.md`.
3. Vérifier que la CI est verte sur `master` :
   `./scripts/ci/lint.sh` puis les scripts `scripts/ci/client-*.sh` concernés.
4. Commit et push de `master` (jamais de tag avant que la CI soit verte).

## 2. Pousser le tag

```sh
git tag -s vX.Y.Z -m "TorDNS vX.Y.Z"
git push origin vX.Y.Z
```

Le workflow `.github/workflows/release.yml` se déclenche uniquement sur un tag
`v*.*.*`. Il refuse un tag différent de `noeud/VERSION`, construit les clients
et les images, crée une **release brouillon** et n'appelle aucune clé de
signature.

## 3. Attendre la CI et contrôler le brouillon

1. Attendre la fin du workflow « Release » dans Actions.
2. Vérifier que la release brouillon contient :
   - les archives et paquets Linux, les installateurs Windows, les APK, le
     `.pkg` et le binaire macOS universel ;
   - `SHA256SUMS` et les attestations de provenance ;
   - `images.txt` avec les empreintes `@sha256:…` des images GHCR.
3. Télécharger la release dans un dossier de travail hors du dépôt :

```sh
gh release download vX.Y.Z --repo garybourbier/tordns --dir /hors/depot/release-vX.Y.Z
cd /hors/depot/release-vX.Y.Z
sha256sum -c SHA256SUMS
```

4. Vérifier les attestations :

```sh
for f in *; do
  [ "$f" = SHA256SUMS ] && continue
  gh attestation verify "$f" --repo garybourbier/tordns
done
```

## 4. Signer les APK

La clé Android et son mot de passe restent hors du dépôt et hors de `dist/`.

```sh
./outils/signer-apk.sh \
  --cle /hors/depot/android-release.jks \
  --alias tordns \
  --mot-de-passe /hors/depot/android-motdepasse.txt \
  --sortie /hors/depot/apk-signes \
  /hors/depot/release-vX.Y.Z/*.apk
```

Le script vérifie chaque APK avec `apksigner verify` et écrit
`/hors/depot/apk-signes/SHA256SUMS`. Remplacer les APK non signés de la
release par les APK signés et leurs sommes à l'étape 6.

## 5. Construire et signer le manifeste

Le manifeste reprend les URLs, tailles et SHA-256 de la release et les
empreintes d'images de `images.txt`. Il est signé hors ligne avec la clé
Ed25519 de publication.

```sh
go build -o /hors/depot/tordns-signer ./outils/publier

/hors/depot/tordns-signer manifeste \
  --depuis-release /hors/depot/release-vX.Y.Z \
  --base-url https://github.com/garybourbier/tordns/releases/download/vX.Y.Z \
  --dossier /hors/depot/cle-publication \
  --version N \
  --adresse coeur=<adresse .onion publique> \
  --sortie /hors/depot/manifeste
```

`--version N` est un entier strictement croissant, indépendant de `X.Y.Z`.
`--depuis-release` vérifie `SHA256SUMS` ; ajouter `--attestations` pour faire
vérifier chaque fichier par `gh attestation verify`. Une somme ou une
attestation fausse fait échouer la commande. Ne jamais mettre la clé privée
dans le dépôt.

## 6. Téléverser et publier

1. Ajouter à la release brouillon `manifeste.json`, `manifeste.json.sig`, les
   APK signés et le `SHA256SUMS` recalculé :

```sh
gh release upload vX.Y.Z \
  /hors/depot/manifeste/manifeste.json \
  /hors/depot/manifeste/manifeste.json.sig \
  /hors/depot/apk-signes/*.apk \
  /hors/depot/apk-signes/SHA256SUMS \
  --repo garybourbier/tordns --clobber
```

2. Contrôler une dernière fois le brouillon dans l'interface GitHub.
3. Publier la release **manuellement** dans l'interface (ou
   `gh release edit vX.Y.Z --draft=false --repo garybourbier/tordns`).
4. Vérifier depuis un poste vierge :

```sh
go run ./outils/publier verifier --manifeste manifeste.json \
  --signature manifeste.json.sig --cle <clé publique>
```

## 7. Nœud depuis GHCR

La release joint `images.txt`. Pour installer un nœud avec les images
publiées, par empreinte :

```sh
cp /hors/depot/release-vX.Y.Z/images.txt noeud/images.txt
sudo ./noeud/installer.sh --images ghcr
```

Sans `--images ghcr`, l'installeur construit les images locales : c'est le
défaut tant qu'aucune version n'est publiée. `TORDNS_IMAGES=ghcr` dans
l'environnement produit le même choix que `--images ghcr`.
