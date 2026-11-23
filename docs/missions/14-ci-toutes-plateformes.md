# Mission 14 — CI : compiler et tester toutes les plateformes existantes

But : à chaque push et pull request, GitHub Actions compile et teste le nœud et les trois
clients existants pour toutes leurs architectures. Rien n'est publié par ce workflow.

## À livrer

- `scripts/ci/` : un script par produit, **appelé à l'identique en local et par la CI**,
  qui prend l'architecture en argument et dépose ses fichiers dans `dist/<produit>/` :
  - `client-linux.sh <amd64|arm64|armv7>` : `go test ./...` puis binaire statique
    (`CGO_ENABLED=0`, `-trimpath`, `-ldflags "-s -w -buildid="`), archive `.tar.gz`
    (binaire + unités systemd + README), paquet `.deb` pour amd64 et arm64 (`dpkg-deb`,
    sans dépendance d'outil tiers). Le binaire de mise à jour `cmd/maj` est inclus.
  - `client-windows.sh <x86_64|aarch64>` : `cargo test` (sur l'hôte), puis exe par
    architecture et installateur NSIS par architecture avec la `wintun.dll` de la même
    architecture (téléchargée depuis wintun.net, **SHA-256 épinglé dans le script**).
    Le `.nsi` reçoit l'architecture en paramètre (`/DARCH=…`) ; un installateur aarch64
    refuse de s'installer sur x64 et inversement.
  - `client-android.sh` : `construire.sh` étendu à **arm64-v8a, armeabi-v7a, x86_64**
    (bibliothèque Arti par ABI, alignement 16 Kio pour toutes), un APK par ABI et un APK
    universel. En CI l'APK est signé avec une **clé de débogage jetable générée dans le job**
    et nommé `…-NON-SIGNE-POUR-PUBLICATION.apk` : la clé de publication reste chez Gary.
  - `noeud-images.sh <amd64|arm64>` : construit chaque Dockerfile du nœud, du serveur et du
    contrôleur pour l'architecture (`docker buildx`, `--platform`), sans pousser.
- `.github/workflows/ci.yml` :
  - déclencheurs `push` et `pull_request` sur `master` ; `concurrency` qui annule les
    exécutions dépassées ; `permissions: contents: read`.
  - jobs : Linux (matrice amd64/arm64/armv7 sur `ubuntu-latest`, arm64 aussi sur
    `ubuntu-24.04-arm` pour lancer les tests en natif), Windows (x86_64 sur
    `windows-latest`, aarch64 sur `windows-11-arm` ; la compilation croisée MinGW reste
    possible sur Linux pour x86_64), Android (`ubuntu-latest`, SDK/NDK aux versions de
    `construire.sh`, installés avec somme vérifiée), images (matrice amd64/arm64 avec
    `docker/setup-qemu-action` et `buildx`).
  - les fichiers produits sont envoyés en *artifacts* (rétention 7 jours), jamais en release.
  - caches Go, cargo et Gradle-less SDK pour ne pas tout retélécharger.
- `scripts/ci/lint.sh` : `actionlint`, `shellcheck` sur tous les `.sh`, `gofmt -l`,
  `cargo fmt --check`, `go vet`. Appelé par la CI en premier job.
- `.github/dependabot.yml` : mises à jour hebdomadaires des actions, des modules Go et des
  crates (les PR Dependabot passent par la même CI).

## Refus et pièges à couvrir

Une action non épinglée par empreinte fait échouer `lint.sh`. Une `wintun.dll` dont le
SHA-256 diffère arrête le build. Un binaire Linux non statique (`ldd` le voit) arrête le build.

## Preuve (`scripts/verifier-m14.sh`)

`lint.sh` vert ; en local : client Linux amd64 + arm64 + armv7 (vérifier l'architecture avec
`file`), `.deb` amd64 installable dans un conteneur Debian propre (`dpkg -i` puis
`tordns-client --version`), exe Windows x86_64 + installateur, APK des trois ABI (lister les
`.so` de chaque APK, contrôler l'alignement 16 Kio), images nœud amd64 et arm64 construites.
NON PROUVÉ attendu : les runners `windows-11-arm` et `ubuntu-24.04-arm` (premier push).
