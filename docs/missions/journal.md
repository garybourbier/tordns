# Journal du chantier 2

Une entrée par mission : fait, reste, demandé à qui.

## Mission 7 — Durcissement (22/11/2026)

- **Fait** : limite de débit par circuit Tor via PROXY v2 (Tor → Caddy →
  passerelle, table bornée en mémoire, purge, plafond global conservé) ;
  `SocksPort 0` et client Tor de test séparé (profil `test`, aucun port
  publié) ; PoW, `HiddenServiceMaxStreams 64` avec fermeture du circuit,
  `VanguardsLiteEnabled 1` ; preuve de bout en bout (`example.com` AD,
  `dnssec-failed.org` SERVFAIL, 429 sur un circuit puis 200 sur un autre,
  journaux sans nom de domaine) ; README serveur et racine remis d'accord
  avec le code.
- **Reste** : l'effet réel de la PoW derrière Onionbalance n'est pas mesuré
  (prévu mission 9) ; l'installation et le service Windows restent non
  prouvés hors Windows (missions 5-6) ; aucun test sur un VPS distant.
- **Demandé à qui** : rien de bloqué, aucune demande. La question PoW/Onionbalance
  revient à la mission 9 (Gary/Claude pour la relecture).

## Mission 13 — Clients : cache, fuites, paquets hostiles (22/11/2026)

- **Fait** : les trois caches (Linux, Windows, Android) expirent au plus petit
  TTL de la section réponse, et NXDOMAIN/NODATA suivent le TTL négatif du SOA
  (minimum du TTL et de MINIMUM, RFC 2308), avec plafond 1 h, TTL nul non caché
  et TTL servi décroissant. Diagnostic de fuites : Linux `--diagnostic`
  (resolv.conf IPv4/`::1`/stub systemd, politiques DoH) avec code 1 s'il reste
  une fuite ; Windows `--diagnostic` (netsh IPv4/IPv6, DoH système et
  navigateur, SMHNR) ; Android lit le DNS privé (DoT) et guide vers
  « Désactivé ». Chaque client absorbe 10 000 paquets aléatoires sans panique.
  `scripts/verifier-m13.sh` passe en entier (27 tests Windows, 33 vérifications
  Android, tests Go, compilation Android, diagnostic sur fixture qui fuit puis
  corrigée).
- **Reste** : le diagnostic Windows réel (netsh/registre) et le bandeau DoT sur
  un appareil Android n'ont pas été exécutés ici (aucun hôte Windows/Android) ;
  le DoH des profils de navigateur n'est pas lisible de façon fiable, seules
  les politiques d'entreprise et le réglage Android sont inspectés.
- **Demandé à qui** : rien de bloqué. Pour une preuve sur matériel réel,
  demander à Gary un passage Windows 11 et un appareil Android (DNS privé
  activé puis désactivé) ; sinon la relecture Claude suffit.

## Mission 8 — Nœud installable (22/11/2026)

- **Fait** : `noeud/installer.sh` (POSIX sh, idempotent) vérifie Debian 12/13
  et la RAM, installe Docker depuis les paquets Debian, crée l'utilisateur
  système `tordns`, `/opt/tordns` et `/var/lib/tordns` (0700), génère le
  `torrc`, laisse Tor créer l'identité du service caché, pose
  `tordns.service` et affiche l'adresse d'instance (`tordns-adresse`).
  `--maitresse` écrit `ob_config` et active
  `HiddenServiceOnionbalanceInstance 1` (préparation mission 9), sans jamais
  toucher aux clés, y compris quand on le retire. `desinstaller.sh` retire
  service, conteneurs et code mais **conserve les clés** ; leur suppression
  exige `--supprimer-cles` et la confirmation tapée « SUPPRIMER ». Page
  publique `/.well-known/tordns/etat` (version, Unbound, Tor,
  charge faible/moyenne/forte) sans aucun compteur. Stack bornée à 640 Mio de
  mémoire et CPU plafonné, journaux Docker coupés. Preuve
  `scripts/verifier-m08.sh` : installation réelle dans une racine jetable,
  identité Tor réelle, DoH POST par le `.onion` (HTTP 200, ID conservé,
  RCODE 0), page d'état lue par Tor, relance avec clé et adresse identiques,
  préparation Onionbalance, désinstallation gardant les clés puis suppression
  après confirmation.
- **Reste** : l'installation des paquets Docker par `apt`, l'activation réelle
  de systemd et une exécution dans un conteneur/VM Debian vierge n'ont pas pu
  être faites ici (ni root ni Debian jetable) ; le bac à sable utilise le
  Docker de la machine de développement. Onionbalance et les mises à jour sont
  hors mission 8.
- **Demandé à qui** : à Gary, un passage `sudo ./noeud/installer.sh` sur un
  VPS Debian 12/13 vierge pour valider apt et systemd ; sinon la relecture
  Claude des scripts suffit.

## Mission 9 — Redondance Onionbalance (22/11/2026)

- **Fait** : contrôleur séparé (`controleur/`) avec Tor et onionbalance 0.2.4,
  authentification au contrôle Tor par socket Unix, génération de
  `maitresse.key`/`maitresse.onion` (0600/0700) et d'une config depuis un pool
  texte. `noeud/installer.sh` accepte `--prefixe` et `--sous-reseau`, et
  `noeud/docker-compose.yml` est paramétrable : trois nœuds complets
  (`tordns-m09-1..3`) tournent sur la même machine, chacun avec son réseau et
  son instance. Caddy autorise le CIDR complet par variable. Documentation
  `docs/redondance.md` (schéma, ajout/retrait d'un nœud, pertes, sauvegarde
  `age`, rotation de clé, plafond de 10 instances, PoW). Preuve
  `scripts/verifier-m09.sh` : publication réelle de l'adresse maîtresse en
  63–78 s, DoH par le `.onion` maître (10/10, ID conservé, RCODE 0), trois
  instances à 3 points d'introduction chacune, descripteur maître à 6 points,
  durée déclarée 180 min, PoW présente sur les instances et absente du maître,
  arrêt d'un nœud (10/10 immédiatement, 10/10 après 300 s, 2 des 6 points
  encore au descripteur), arrêt du contrôleur (10/10 encore servies).
- **Reste** : les trois nœuds partagent un seul hôte, pas trois VPS distincts ;
  la survie du descripteur au-delà des quelques minutes mesurées après la
  perte du contrôleur n'a pas été attendue en entier (seule la durée déclarée
  de 180 min est connue) ; la tenue au-delà de trois instances n'est pas
  testée ; la restauration réelle d'une sauvegarde chiffrée n'a pas été
  exécutée.
- **Demandé à qui** : à Gary, trois VPS distincts (ou au moins deux) pour
  mesurer la perte d'un site réel, et un test de restauration `age` sur une
  machine hors ligne ; sinon la relecture Claude de `docs/redondance.md`
  suffit.

## Mission 11 — Mises à jour signées (22/11/2026)

- **Fait** : bibliothèque `outils/manifeste` (signature Ed25519 sur les octets
  exacts, expiration, taille/SHA-256, images obligatoirement
  `nom@sha256:…`, refus de rejeu, rotation par `cle_suivante`) et outil
  `outils/publier` (`cle`, `manifeste`, `verifier`, hors ligne, stdlib seule).
  `noeud/maj` applique un manifeste récupéré par Tor : tirage Docker par
  empreinte via un override compose, sonde de santé, retour automatique aux
  images précédentes si elle échoue. `client-linux/cmd/maj` fait de même pour
  le binaire, remplacement atomique puis retour arrière si le service ne
  redémarre pas. Units `tordns-maj.service`/`.timer` (6 h, décalage aléatoire
  de 30 min) et équivalent client, miroir `/maj/` servi par Caddy depuis
  `/var/lib/tordns/maj`, client Tor dédié dont le SOCKS n'écoute que sur la
  boucle locale, installeur et désinstalleur mis à jour, documentation de
  publication et de rotation. Preuve `scripts/verifier-m11.sh` : tests Go des
  quatre modules, v2 appliquée au nœud et au client, rejeu v1 refusé, manifeste
  altéré refusé, image par étiquette refusée, image cassée → v1 rétablie, service
  client en échec → binaire précédent rétabli.
- **Reste** : le transport Tor réel, un vrai registre Docker (tirage par
  empreinte non exécuté contre un registre), un redémarrage systemd réel, la
  construction de `tordns-maj` par l'installeur sur un Debian vierge, et une
  rotation de clé sur un parc réel n'ont pas été prouvés ; les tests utilisent
  HTTP local, un docker et un systemctl factices.
- **Demandé à qui** : à Gary, un registre d'images (GHCR) avec des empreintes
  réelles et un VPS Debian pour l'installation complète ; sinon la relecture
  Claude du format et des refus suffit.

## Mission 10 — Registre et admission des bénévoles (23/11/2026)

- **Fait** : registre Go dans `controleur/registre` (inscription en deux temps,
  défi aléatoire vérifié sur `/.well-known/tordns/defi`, limites par circuit Tor
  via PROXY v2 et par jour, état persistant, page publique sans contact), sondes
  à domaines tirés au hasard comparant adresses A, RCODE et bit AD à Unbound,
  admission après quarantaine (72 h par défaut) et éviction immédiate sur
  mensonge DNSSEC/fausse IP ou indisponibilité prolongée. Pool communauté écrit
  par le registre, second Onionbalance avec clé distincte, rechargement par
  timer de deux minutes. Côté nœud : route de défi dans Caddy/etat, outil
  `tordns-inscrire`, option `installer.sh --rejoindre`. Preuve
  `scripts/verifier-m10.sh` : tests Go (honnête admis, menteur évincé, fausse
  IP évincée, défi absent refusé, limites, PROXY), inscription réelle
  registre+nœud factice avec admission et pool, page publique, configuration du
  second Onionbalance, compose valide.
- **Reste** : le transport Tor réel, l'émission effective du PROXY v2 par Tor,
  la publication du service caché du registre et du second descripteur, des
  nœuds bénévoles réels, la résolution DNSSEC réelle (AD/SERVFAIL simulés) et
  l'exécution de `installer.sh --rejoindre` sur un Debian vierge n'ont pas été
  prouvés. Les limites par circuit utilisent le PROXY v2 ; sans Tor, la source
  réseau sert de repli.
- **Demandé à qui** : à Gary, une instance du contrôleur avec Tor et un VPS
  bénévole pour vérifier la publication du second descripteur et le PROXY v2 ;
  sinon relecture Claude du registre et du format d'inscription.

## Mission 12 — Mises à jour Windows/Android, adresses signées, DNSSEC (23/11/2026)

- **Fait** : vérification du manifeste partagée en Rust entre Windows et Android
  (`outils/manifeste-rust`), mise à jour Windows (`--maj`, téléchargement par
  Tor, SHA-256, installateur silencieux, cache de retour arrière, tâche
  planifiée NSIS) et Android (vérification en arrière-plan, notification,
  session `PackageInstaller`, même clé APK documentée, piste F-Droid). Liste
  d'adresses cœur/communauté lue dans le dernier manifeste vérifié, avec modes
  « cœur seulement » (défaut), « secours » et « communauté » dans les trois
  clients. DNSSEC validé côté Linux (`miekg/dns`, chaîne DS/DNSKEY depuis la
  racine), Windows (`hickory-proto`) et Android (`dnsjava`) ; une fausse
  adresse ou une signature altérée devient SERVFAIL. Preuve
  `scripts/verifier-m12.sh` : tests Go/Rust/Java, exe Windows croisé et lancé
  sous Wine, APK v2 signé avec symboles JNI et dnsjava, manifeste signé par
  l'outil Go accepté par Rust puis rejeu/signature altérée refusés.
- **Reste / non prouvé** : installation réelle Windows et redémarrage du
  service (pas de VM Windows), installation réelle de l'APK et session
  PackageInstaller (pas d'appareil), téléchargements par Tor réels (sources
  locales), validation DNSSEC contre l'Internet réel (fixtures signées en
  mémoire), preuves de négation NSEC/NSEC3 complètes côté Linux, rotation de
  clé sur parc réel, dépôt F-Droid.
- **Demandé à qui** : à Gary, une VM Windows pour l'installateur/tâche
  planifiée et un appareil Android pour la session d'installation ; à Claude,
  une relecture des chemins de retour arrière Windows et de la conservation de
  la clé APK. Les preuves de négation NSEC/NSEC3 restent à confier à Claude.

## Vérification intégrée après la mission 12 (23/11/2026)

- **Fait** : les sept scripts `scripts/verifier-m07.sh` à `verifier-m13.sh`
  ont été rejoués sur l'arbre final. Plusieurs défauts d'intégration sont corrigés.
  (1) Le contrôleur ne démarrait plus : Tor 0.4.9 refuse une cible de service
  caché par nom non résolvable (`registre:8080`), alors que le registre attend
  Tor sain — cycle cassé en épinglant le registre en `172.28.58.10` et en
  ciblant cette IP dans `torrc`. (2) Unbound du contrôleur redémarrait en
  boucle : rootfs en lecture seule et `cap_drop: ALL` empêchaient l'entrypoint
  de préparer `/var/lib/unbound` ; ajout des mêmes capacités que le nœud
  (`CHOWN`, `DAC_OVERRIDE`, `SETUID`, `SETGID`) et d'un `tmpfs` inscriptible.
  (3) Les preuves M09 (accent « maîtresse »), M11 (cache de manifeste hors de
  `/var/lib`) et M13 (jars `dnsjava` au classpath) suivaient encore l'ancien
  comportement.
- **Preuves** : M07, M08, M10, M11, M12 et M13 `code=0` ; M09 `code=0` avec
  vraie publication Tor (maître joignable en 60 s, 10/10 DoH, continuité après
  arrêt d'un nœud et perte du contrôleur).
- **Reste / non prouvé** : les limites déjà notées pour M09 (un seul hôte,
  trois instances, survie mesurée quelques minutes) et M12 (VM Windows,
  appareil Android, DNSSEC contre l'Internet réel, NSEC/NSEC3 Linux) restent
  inchangées.
- **Demandé à qui** : à Gary, un second hôte pour M09 et une VM Windows/appareil
  Android pour M12 ; à Claude, la relecture des preuves de négation NSEC/NSEC3.

## DNSSEC Linux : négation NSEC/NSEC3 (23/11/2026)

- **Fait** : le validateur Linux suit désormais uniquement les vraies
  délégations (un DS absent sur un nom d'hôte ne fait plus passer la zone pour
  non signée) et vérifie les preuves de négation : NXDOMAIN avec absence du nom
  et du wildcard, NODATA au nom ou via un wildcard, délégation sans DS par NSEC
  ou NSEC3 opt-out. Les RRset non signés ajoutés à une réponse signée sont
  refusés ; une cible de CNAME située dans une zone non signée reste acceptée
  en mode `auto`. Les tests couvrent aussi un nom d'hôte, un NSEC3 qui annonce
  le type demandé, un NXDOMAIN sans preuve de wildcard et une injection de
  RRset non signé.
- **Reste / non prouvé** : les fixtures sont générées en mémoire, aucun échange
  avec les racines ou les zones réelles n'est exécuté ici ; le cas NSEC3
  opt-out d'un nom vide non terminal peut être classé comme délégation non
  signée (comportement conservateur, à confirmer sur des zones réelles).
- **Demandé à qui** : à Claude, relecture des preuves de négation et de la
  classification opt-out ; à Gary, un essai contre quelques zones signées
  réelles (NSEC et NSEC3) avant diffusion.

## Relecture Claude du chantier 2 (23/11/2026)

- **Corrigé** (tests d'attaque rouges avant le correctif) :
  - `06c4048` DNSSEC Linux : les signatures hors de leur période de validité
    étaient acceptées (rejeu sans fin), et une zone pouvait signer une zone
    voisine (`example.test` signait `badexample.test` : miekg/dns ne compare
    que des suffixes de chaîne).
  - `b084858` Windows : `C:\ProgramData\TorDNS\maj` était inscriptible par
    tout utilisateur alors que la tâche SYSTEM y lit l'état, la clé de
    rotation et les installateurs → élévation en SYSTEM. Droits verrouillés
    (NSIS + re-verrouillage avant chaque mise à jour), temporaire recréé en
    exclusivité ; l'installateur initial est désormais déposé (sans lui la
    première mise à jour était toujours refusée).
  - `9c1aa4e` Registre : `/etat` publiait le contact et le défi des candidats.
- **Reste / non prouvé** : l'effet réel d'icacls (Wine n'a pas d'ACL NTFS) ;
  la sonde du registre exige des IP identiques à la référence (un domaine à
  réponses variables, CDN, peut disqualifier un bénévole honnête : comparer
  RCODE/AD et exiger une intersection) ; une mise à jour Linux refusée par le
  service est retentée à chaque passage du minuteur.
- **Demandé à qui** : à Gary, une VM Windows pour vérifier les droits de
  `maj\` après installation.

## Mission 19 — Restes de la relecture du 23/11 (23/11/2026)

- **Fait** : la sonde du registre accepte désormais une intersection d'adresses
  A (CDN et tourniquets), refuse un RCODE ou un bit AD différent, et traite un
  ensemble disjoint comme un mensonge sur une réponse signée mais comme un
  simple doute sur une réponse non signée. Les doutes sont comptés sur des
  domaines distincts, conservés sous forme d'empreintes (aucun nom dans l'état
  public) et disqualifient au seuil configurable `-doutes-max` (3 par défaut).
  Les trois mécanismes de mise à jour retiennent la version rejetée
  (`rejetee: N`) : le client Linux et le nœud après un retour arrière, le client
  Windows après le relancement de l'installateur précédent ; une version
  supérieure est toujours essayée. Preuve `scripts/verifier-m19.sh` : tests Go
  et Rust ciblés, puis M10, M11 et M12 rejouées vertes.
- **Reste / non prouvé** : les CDN et tourniquets réels, l'Internet réel
  (`dnssec-failed.org` est imité localement), le seuil de doutes sur un parc
  réel, un redémarrage systemd réel, un service Windows réel et ses droits
  NTFS, le transport Tor des mises à jour. Les tests d'installation utilisent
  un serveur HTTP local et un `systemctl` factice.
- **Demandé à qui** : à Gary, un essai contre quelques domaines CDN réels et
  une VM Windows pour le service ; à Claude, une relecture du seuil de doutes
  et de la conservation de `rejetee` après un retour arrière.

## Mission 14 — CI de toutes les plateformes (23/11/2026)

- **Fait** : scripts `scripts/ci/` pour Linux (amd64, arm64, armv7, binaires
  statiques, archives et .deb), Windows (exe x86_64/aarch64 et installateur
  NSIS, wintun.dll 0.14.1 aux SHA-256 épinglés), Android (arm64-v8a,
  armeabi-v7a, x86_64, APK par ABI et universel, `.so` en LOAD 0x4000 et
  zipalign 16 Kio) et images Docker du nœud, du serveur et du contrôleur en
  amd64/arm64. Workflow `ci.yml` avec actions épinglées par empreinte,
  permissions `contents: read`, concurrence, artifacts de 7 jours et caches ;
  `dependabot.yml` hebdomadaire. `scripts/ci/lint.sh` couvre actionlint,
  shellcheck, gofmt, go vet et cargo fmt ; `client-linux --version` ajouté
  pour le test du paquet. Preuve `scripts/verifier-m14.sh` : lint vert, trois
  binaires Linux statiques, .deb amd64 installé dans un Debian propre,
  exe/installateur Windows x86_64, APK des trois ABI, images amd64/arm64
  inspectées.
- **Reste / non prouvé** : les runners `ubuntu-24.04-arm` et
  `windows-11-arm`, l'exécution réelle du workflow, des caches et des
  artifacts (à vérifier au premier push) ; l'installateur aarch64 et son refus
  réel sur x64 (pas de chaîne ARM64 locale) ; les versions de Rust/JDK/SDK du
  runner peuvent différer de cette machine.
- **Demandé à qui** : à Gary, pousser la branche et vérifier le premier run
  GitHub ainsi que le téléchargement des artifacts ; à Claude, relire les
  empreintes d'actions et les scripts de packaging.

## Mission 15 — Client macOS (23/11/2026)

- **Fait** : le cœur du client est désormais dans `client-linux/relais`
  (relais, cache, DNS, DNSSEC, DoH, adresses signées), partagé par Linux et
  macOS sans duplication. `client-macos` ajoute un service launchd, le réglage
  DNS de chaque service actif par `networksetup` avec sauvegarde/restauration
  (`dns-original.json`, root:wheel 0700), un diagnostic `scutil --dns`, le
  refus de démarrer sans SOCKS Tor, et une mise à jour signée avec remplacement
  atomique, `launchctl kickstart -k` et `rejetee`. Binaires amd64/arm64
  compilés, universel via `lipo` sur macOS, `.pkg` non signé via `pkgbuild` et
  scripts d'installation/désinstallation. `scripts/verifier-m15.sh` teste le
  cœur, les analyseurs sur fixtures, les deux Mach-O et vérifie launchd/scutil/
  networksetup/SOCKS. Le workflow ajoute `macos-latest` et `macos-15-intel`
  (`macos-13` n'est plus un label GitHub en 2026).
- **Reste / non prouvé** : lancement réel sur un Mac, `launchd`,
  `networksetup`/`scutil`, restauration DNS après arrêt, binaire universel
  (`lipo` absent ici), `.pkg`, signature Developer ID et notarisation Apple.
  Aucun secret Apple n'est utilisé.
- **Demandé à qui** : à Gary, un Mac Intel et un Mac Apple Silicon pour le
  lancement réel et le `.pkg` ; à Claude, relire la sauvegarde/restauration DNS
  et le chemin de mise à jour launchd.

## Mission 16 — CD, release brouillon et images GHCR (23/11/2026)

- **Fait** : `.github/workflows/release.yml` ne se déclenche que sur un tag
  `v*.*.*`, vérifie que le tag correspond à `noeud/VERSION`, réutilise les
  scripts `scripts/ci/`, construit Linux/Windows/macOS/Android, pousse les
  images multi-arch sur GHCR avec `images-release.sh`, écrit `images.txt` avec
  les empreintes, assemble les noms `tordns-<produit>-<version>-<os>-<arch>`,
  `SHA256SUMS`, les attestations de provenance et crée la release **brouillon**
  avec les notes de `CHANGELOG.md`. `tordns-signer manifeste --depuis-release`
  vérifie les sommes (et les attestations avec `--attestations`), déduit les
  cibles et les images ; `outils/signer-apk.sh` signe les APK, vérifie avec
  `apksigner verify` et recalcule les sommes. Le nœud accepte
  `--images ghcr` (ou `TORDNS_IMAGES=ghcr`) avec les images épinglées de
  `images.txt` ; la construction locale reste le défaut. Procédure complète
  dans `docs/publier-une-version.md`. `scripts/verifier-m16.sh` est vert et
  M14/M15/M19 ont été rejouées vertes après ces changements.
- **Reste / non prouvé** : exécution réelle du workflow sur un tag, attestations
  GitHub, connexion et push GHCR multi-arch, création du brouillon, `gh release
  download`, vérification `gh attestation verify`, publication finale. Aucun
  tag n'a été poussé et aucune release n'a été publiée. `actions/attest-build-provenance`
  couvre tous les fichiers de `dist/release/*` en une invocation ; à confirmer
  au premier tag que chaque fichier reçoit bien son attestation.
- **Demandé à qui** : à Gary, pousser le premier tag et contrôler le brouillon
  et GHCR ; à Claude, relire `release-assembler.sh` et `images-release.sh` au
  premier passage réel.

## Mission 17 — Site de présentation sur GitHub Pages (23/11/2026)

- **Fait** : `site/` contient une page française et une page anglaise
  complètes, du CSS local, un schéma SVG et un petit script de mise en avant de
  la plateforme, sans cookie, stockage, police distante ni traceur. Les 13
  noms de téléchargements viennent de `site/telechargements.json`, aussi
  utilisé par `release-locale.sh` et `release-assembler.sh`. Les liens pointent
  vers `releases/latest/download/`, avec `SHA256SUMS` et la commande
  `gh attestation verify`. `.github/workflows/pages.yml` génère puis déploie
  `site/` sur `master` avec `pages: write` et `id-token: write` sur le seul job
  de déploiement. `SECURITY.md` ne donne aucune adresse personnelle et renvoie
  au signalement privé GitHub. `scripts/verifier-m17.sh` vérifie les liens, les
  URLs (toutes github.com), l'absence de traceur, la génération idempotente et
  capture les deux pages à 360 et 1280 px : aucun débordement horizontal.
- **Reste / non prouvé** : la page en ligne, car Gary doit activer Pages avec
  la source « GitHub Actions » dans les réglages du dépôt. `tidy`/`vnu` ne sont
  pas installés ici ; la validation HTML se limite à l'analyseur Python et au
  rendu Chromium. Les captures utilisent `scripts/ci/site-capture.py` et
  `websocket-client` (présent localement).
- **Demandé à qui** : à Gary, activer Pages et vérifier l'URL publiée ; à
  Claude, relire les textes de sécurité et les liens de téléchargement au
  premier déploiement.

## Mission 18 — README à jour (23/11/2026)

- **Fait** : README réécrit dans l'ordre demandé : présentation et badges,
  tableau des téléchargements par plateforme/architecture, démarrage rapide
  Linux/Windows/macOS/Android, nœud et images GHCR, architecture Onionbalance /
  registre / mises à jour, modèle de menace et limites reprises du journal,
  développement, historique des missions 1 à 19 et licence MIT. Les 13 noms de
  téléchargements viennent de `site/telechargements.json`, donc de la même
  source que la release. Les README des quatre clients et du nœud renvoient aux
  téléchargements de la release ; le nœud documente `--images ghcr`.
  `scripts/verifier-m18.sh` vérifie les sections, l'absence des formulations
  marketing, les liens relatifs, l'alignement exact des 13 liens avec la liste
  de release et les renvois des composants.
- **Reste / non prouvé** : le rendu réel du README et des badges sur GitHub, et
  les liens externes (GitHub, shields.io, page Pages), ne sont pas visités ici.
- **Demandé à qui** : à Gary, jeter un œil au README rendu après le premier
  push ; à Claude, relire le modèle de menace et la liste des limites.

## Mission 20 — Fuzzing de l'analyse DNS (23/11/2026)

- **Fait** : cinq cibles Go (`FuzzPasserelleDoH`, `FuzzRelaisClient`,
  `FuzzValiderDNSSEC`, `FuzzEnTeteProxy`, `FuzzManifeste`) avec corpus de
  départ dans `testdata/fuzz` (15 fichiers : A, réponses, paquets courts,
  pointeurs de compression en boucle, PROXY v2 IPv4, manifeste). Deux cibles
  `cargo-fuzz` : décodeur DNS Windows et `tordns_manifeste::verifier`.
  `scripts/ci/fuzz.sh` lance Go ou Rust ; `.github/workflows/fuzz.yml` tourne
  chaque lundi, 10 min par cible, avec `permissions: contents: read` et
  archivage du corpus. Preuve `FUZZ_DUREE=2m ./scripts/verifier-m20.sh` :
  5 cibles Go × 2 min et 2 cibles Rust × 2 min, environment nightly 1.102 et
  cargo-fuzz 0.13.2 installés localement, aucun plantage ; tests de régression
  Go/Rust verts. Aucun correctif de plantage n'a été nécessaire.
- **Reste / non prouvé** : la durée réelle de 10 min par cible dans GitHub
  Actions et l'archivage des corpus générés par la CI ; les cibles Rust
  exigent nightly + cargo-fuzz, absents d'une machine sans ces outils.
- **Demandé à qui** : à Gary, lancer une fois le workflow Fuzz à la main et
  conserver les corpus s'ils grossissent ; à Claude, relire les cibles Rust et
  la classification des entrées non valides.

## Mission 21 — Compilations reproductibles (24/11/2026)

- **Fait** : Go est forcé à 1.23.7 par `GOTOOLCHAIN=go1.23.7` et
  `toolchain go1.23.7` (Linux, macOS), Rust à 1.96.1 par
  `client-windows/rust-toolchain.toml`, et les bases Docker sont épinglées par
  empreinte. Linux utilise `-buildvcs=false`, `ar rcsD`, `tar --mtime` et
  `gzip -n` ; Windows ajoute `--locked`, le remappage des chemins, un
  horodatage PE normalisé (`pe-timestamp.py`) et `touch` des entrées NSIS ;
  Android trie les entrées ZIP et les date avec `SOURCE_DATE_EPOCH`. Les APK
  publiés sont désormais réellement non signés (`-NON-SIGNE-POUR-PUBLICATION`),
  la copie debug restant séparée. `scripts/ci/reproduire.sh` et
  `docs/reproduire.md` reconstruisent le tag en conteneur et documentent les
  limites. Preuve `./scripts/verifier-m21.sh` : deux constructions successives
  donnent les mêmes octets pour Linux, Windows x86_64 et les quatre APK ;
  `./scripts/ci/lint.sh` est vert. M14, M15 et M19 ont été rejouées vertes
  après ces changements.
- **Reste / non prouvé** : macOS et le `.pkg`, la signature Developer ID et la
  notarisation, les images multi-arch (Buildx local sans
  `--rewrite-timestamp`), et l'exécution réelle des workflows CI/release. Aucun
  tag n'a été créé ni poussé ; `reproduire.sh` n'a donc pas été lancé sur un
  tag. Les empreintes des images de base et de Go/Rust devront être vérifiées
  lors du premier passage CI.
- **Demandé à qui** : à Gary, pousser un tag et lancer la CI/release pour
  confirmer la reproductibilité sur macOS, les images multi-arch et le runner
  Windows ; à Claude, relire `reproduire.sh`, `pe-timestamp.py` et les
  Dockerfiles épinglés.

## Mission 22 — Page publique de l'état du réseau (24/11/2026)

- **Fait** : le registre agrège ses sondes cœur et communauté dans
  `/donnees/etat-reseau.json` : nœuds admis et joignables, délais médian et p95
  sur 24 h, taux de réponses DNSSEC correctes et dernière tentative de
  publication du descripteur. L'historique est borné à 720 agrégats horaires
  (30 jours), avec plafond d'échantillons et purge. Les sondes mesurent
  désormais la latence et la justesse sans conserver les noms de domaine. Le
  pool cœur est relu à chaque passe. Les endpoints `/reseau` (HTML, SVG côté
  serveur, aucun JavaScript) et `/reseau.json` servent des données agrégées ;
  les adresses d'instance sont tronquées aux huit premiers caractères, sans
  contact, défi, domaine demandé ni compteur de trafic. La date de publication
  est lue sur le socket de statut d'Onionbalance, avec repli sur un fichier.
  Le pool cœur est recopié dans le volume, et le socket de statut partage un
  volume `run/` entre Onionbalance et le registre. La copie GitHub Pages est
  conditionnée par `TORDNS_PUBLIER_ETAT_RESEAU=oui` et lit `/reseau.json` par
  Tor ; l'adresse `.onion` vient de `TORDNS_REGISTRE_ONION`, avec repli vers
  l'adresse configurée. Preuve `scripts/verifier-m22.sh` : tests d'agrégation,
  de fenêtre et de purge, page et JSON sans adresse complète, sans contact ni
  défi, HTML/SVG sans JavaScript, lint vert. M10, M17, M18 et M19 ont été
  rejouées vertes après ces changements.
- **Reste / non prouvé** : la publication réelle du service caché et la lecture
  par Tor (aucun Tor lancé dans la preuve), le socket d'Onionbalance réel, les
  variables de dépôt et l'exécution du workflow Pages, les délais sur de vrais
  nœuds (mesures simulées). La date affichée est la dernière **tentative** de
  publication rapportée par Onionbalance, pas une confirmation d'upload.
- **Demandé à qui** : à Gary, définir les deux variables de dépôt et lancer le
  workflow Pages une fois avec Tor ; à Claude, relire la conservation des
  échantillons et l'interprétation des dates Onionbalance.

## Mission 23 — Paquet OpenWrt (24/11/2026)

- **Fait** : paquet `client-openwrt/` construit avec les SDK OpenWrt 25.12.6
  épinglés par SHA-256 (ramips/mt7621, mediatek/filogic, x86/64), au format
  `apk` de la version stable actuelle (plus d'`.ipk`). Binaires Go statiques
  `-s -w` (sans UPX) pour mipsel_24kc, mips_24kc, arm_cortex-a7,
  aarch64_cortex-a53 et x86_64, de 4,5 à 5,1 Mo. Service procd
  (`START=95`, redémarrage automatique, rechargé si `/etc/config/tordns`
  change), configuration UCI (adresse, mode, DNSSEC, cache, SOCKS, port,
  dnsmasq, anti-fuite, interface LAN). Le transfert dnsmasq est réglé dans
  l'UCI (`noresolv`, `server=127.0.0.1#5353`), pas dans `/etc/dnsmasq.d` que
  dnsmasq d'OpenWrt ne lit pas ; les serveurs ajoutés par l'utilisateur sont
  conservés et le service les rétablit à l'arrêt. Chaîne nftables
  `tordns_anti_fuite` (hook forward) : rejet du port 53 hors du routeur et du
  DoT 853 depuis le LAN, désactivable par l'option `anti_fuite`. Page LuCI
  minimale (état, adresse, test de fuite, bouton démarrer/arrêter). Job
  `openwrt` ajouté à la CI et à la release, entrées de téléchargement sur le
  site et dans le README.
- **Preuve** `scripts/verifier-m23.sh` : cinq binaires `file` statiques, trois
  paquets `apk` construits par le SDK, contenu du paquet conforme, syntaxes
  shell/JavaScript/JSON, puis image OpenWrt 25.12.6 x86_64 lancée dans QEMU
  (`alpine` + `qemu-system-x86_64`, conteneur **non privilégié**, aucun
  `/dev`, aucun init OpenWrt) : WAN, paquet installé, service actif, relais à
  l'écoute sur 5353, dnsmasq transférant vers `127.0.0.1#5353`, chaîne
  nftables présente, DNS direct et DoT bloqués depuis un client du LAN
  simulé, témoin anti-fuite désactivée autorisant puis réactivée bloquant,
  transfert prouvé par un stub DNS répondant `93.184.216.34`, et aucun nom de
  domaine dans `logread` ni dans la sortie du service. `scripts/ci/lint.sh`
  vert.
- **Reste / non prouvé** : vrai routeur matériel (flash, RAM réelle, Tor qui
  tient dans 256 Mo), Tor et résolution par le `.onion` sur le routeur, paquets
  installés sur mips/arm (seuls les binaires y sont vérifiés), page LuCI
  construite et affichée, rendu nftables sur mips/arm, exécution des workflows
  CI/release. Les essais système n'utilisent aucune adresse réelle.
- **Demandé à qui** : à Gary, flasher un routeur (ramips/mt7621 ou
  mediatek/filogic) et confirmer RAM, Tor et anti-fuite en conditions réelles ;
  à Claude, relire le service procd (restauration des serveurs dnsmasq à
  l'arrêt) et le template nftables.

## Mission 27 — Dossier pour un audit de sécurité externe (24/11/2026)

- **Fait** : `docs/securite/modele-de-menace.md` (4 actifs, 7 adversaires,
  chaque défense renvoyant au fichier qui l'implémente et au vérificateur qui
  la teste, hors périmètre explicite) ; `docs/securite/perimetre-audit.md`
  (tableau des composants, environnement de test hors ligne, hors périmètre,
  8 questions précises à l'auditeur, priorité suggérée) ;
  `docs/securite/problemes-connus.md` (tout le NON PROUVÉ du journal, classé
  par gravité, chaque élément renvoyant à une mission) ;
  `docs/securite/demande-otf.md` (brouillon en anglais, à relire et envoyer
  par Gary) ; `SECURITY.md` complété (versions prises en charge, délais
  d'accusé, d'évaluation et de divulgation coordonnée à 90 jours, renvoi au
  dossier). Aucun contact ni envoi n'a été fait.
- **Preuve** `scripts/verifier-m27.sh` : les cinq documents existent et ont
  leurs sections ; les 84 chemins cités existent ; chaque problème connu
  renvoie à une mission présente au journal (17 missions citées) ; aucune clé,
  aucune adresse `.onion` complète, aucun courriel ; lint vert.
- **Reste / non prouvé** : l'audit lui-même, l'acceptation par un auditeur ou
  par l'OTF, et la pertinence des questions posées (à valider par un tiers).
  Le commit à auditer reste à figer au moment de la demande.
- **Demandé à qui** : à Gary, relire `demande-otf.md`, y mettre la date et le
  commit, puis déposer lui-même la demande ; à Claude, relire le modèle de
  menace et le classement des problèmes connus.

## Mission 24 — image nœud Raspberry Pi (24/11/2026)

- **Fait** : `noeud/raspberry/` (outil de clés `.onion` au format Tor, page
  d'état `/` et `/etat`, `premier-demarrage.sh`, `inscription.sh`, pare-feu
  nftables, unités systemd, `README.md` du matériel), `scripts/ci/image-rpi.sh`
  + `rpi-partitions.py` + `rpi-outils.Dockerfile`. Image `0.8.0` de 614 Mio
  compressés, ajoutée à `site/telechargements.json`, aux gabarits du site et à
  la release (tâche `noeud-rpi`).
- **Comment, sans root** : partitions de Raspberry Pi OS Lite extraites en
  fichiers, éditées par `debugfs` et `mtools` dans un conteneur non privilégié
  (`--user uid:gid`, sans montage ni périphérique), puis réinsérées et
  arrondies à 4 Gio.
- **Choix** : clés générées au premier démarrage (jamais dans l'image),
  SSH et `userconfig` coupés, ce dernier **masqué** (`/dev/null`) car un preset
  le réactive ; partition racine portée à 3 Gio à la construction ; QEMU
  `raspi3b` avec `WatchdogDevice=/dev/watchdog666` dans la copie d'essai
  seulement (le chien de garde émulé redémarre sinon toutes les 13 s).
- **Différence assumée** : l'installation du nœud par `installer.sh --images
  ghcr` se fait au premier démarrage, pas dans l'image — impossible d'exécuter
  Docker dans le rootfs sans privilèges pendant la construction. Le premier
  démarrage attend Docker et avertit si `noeud/images.txt` manque.
- **Preuve** `scripts/verifier-m24.sh` : image sous 2 Go et empreinte vérifiée ;
  inspection hors ligne (aucune clé, aucun marqueur, aucun compte à mot de
  passe, SSH et `userconfig` désactivés, hôte `tordns`, pare-feu en `policy
  drop` sauf le port 80) ; deux démarrages QEMU complets avec « pare-feu
  appliqué » et « terminé », deux clés de 96 octets différentes ; Tor 0.4.9 de
  l'hôte lit la clé et publie une adresse ; lint vert. `code=0`.
- **Reste / non prouvé** : vrai Pi (démarrage, chien de garde, SD, SSD,
  consommation), extension de partition sur carte réelle, installation par
  images GHCR (aucune image publiée correspondant à `noeud/images.txt`),
  inscription réelle au registre, page `tordns.local` vue d'un autre appareil,
  et la tâche `noeud-rpi` de la release, jamais exécutée ici.
- **Demandé à qui** : à Gary, flasher une carte et rapporter le journal série
  du premier démarrage ; à Claude, relire `premier-demarrage.sh` et le
  durcissement des unités systemd.

## Mission 25 — Publication sur F-Droid (24/11/2026)

- **Fait** : `metadata/org.tordns.client.yml` (MIT, NDK `r26b`, Rust par
  `sudo`/`prebuild`, construction confiée à `client-android/scripts/construire.sh`,
  `commit:` sur le SHA de la mission, AutoUpdateMode `Version`, UpdateCheckMode
  `Tags`), métadonnées fastlane fr-FR et en-US (titre, résumés, description,
  journal `800`), `docs/fdroid.md` (procédure de soumission à la main, c'est
  Gary qui ouvre la demande), `client-android/DEPENDANCES.md` (licences et
  empreintes), `scripts/verifier-m25.sh`.
- **Choix** : pas de Gradle. F-Droid accepte des commandes `build:`
  arbitraires, donc la recette appelle le script maison ; il a fallu y dériver
  la version du tag (`scripts/ci/version.sh`) et écrire le manifeste dans une
  copie temporaire, `aapt2` 2.20 ignorant `--version-code`/`--version-name`
  quand le manifeste les déclare.
- **Obstacle** : `fdroid build` refuse les `.jar` versionnés (« Found Fichier
  Java JAR »). `client-android/libs/` disparaît au profit de
  `client-android/scripts/telecharger-libs.sh`, qui récupère dnsjava 3.6.3 et
  slf4j-api 2.0.16 sur Maven Central avec empreintes SHA-256 épinglées dans
  `client-android/build/libs/` (cache local, remplacement d'un jar corrompu
  vérifié).
- **Seconde obstruction** : l'APK portait `debuggable` (option `--debug-mode`
  d'`aapt2 link`), refusé par F-Droid. La construction de publication ne
  l'active plus ; `DEBUG=oui` la remet pour le diagnostic adb documenté.
- **Preuve** `scripts/verifier-m25.sh` : `fdroid lint` officiel sans remarque ;
  `fdroid build --test` officiel (fdroidserver 2.4.2 sous Python 3.14) sur un
  dépôt servi en HTTP local, produisant `0.8.0 (800)` avec trois ABI, dnsjava
  et `TorVpnService` dans le dex ; `fdroid scanner` sans classe non libre ;
  aucune archive Java dans les sources. `code=0`.
- **Non prouvé** : l'acceptation par F-Droid et la construction dans leur
  buildserver (ni libvirt ni leur image ici) ; `sudo`/`prebuild` de la recette
  sont retirés localement puisque Rust, le SDK et le NDK sont déjà installés ;
  aucune capture d'écran fastlane (pas d'appareil) ; la comparaison
  reproductible avec l'APK signé par Gary n'est pas faite.
- **Demandé à qui** : à Gary, ouvrir la demande sur fdroiddata (MR avec
  `metadata/org.tordns.client.yml` et `fastlane/`), puis pousser le tag `v0.8.0`
  que `UpdateCheckMode: Tags` attend ; à Claude, relire la recette et les
  métadonnées avant envoi.

## Mission 26 — Client iOS (24/11/2026)

- **Fait** : la logique Tor/DoH quitte `client-android/rust` pour un crate
  partagé `outils/arti-rust` (`tordns-tor`) ; Android ne garde que le pont JNI,
  iOS un pont C (`client-ios/rust`, ABI de `rust/include/tordns.h`). Livrés
  aussi : application SwiftUI (marche/arrêt, adresses, DNSSEC, test de fuite,
  empreinte mémoire), extension `NEPacketTunnelProvider` limitée au DNS,
  `project.yml` pour `xcodegen` (trois cibles, aucun `.xcodeproj` versionné),
  entitements `packet-tunnel-provider` et groupe d'applications partagé,
  tests de paquets DNS, `scripts/ci/client-ios.sh` et job CI `ios` sur
  `macos-latest` (secrets Apple facultatifs, étape sautée sinon),
  `scripts/verifier-m26.sh`.
- **Choix** : `NEDNSProxyProvider` écarté. La documentation Apple (TN3134 et
  la page du proxy DNS) le réserve aux appareils supervisés, avec un profil
  `com.apple.dnsProxy.managed` installé par MDM depuis iOS 15 : une application
  grand public ne pourrait pas l'activer. Le tunnel de paquets n'inclut aucune
  route (`includedRoutes = []`), annonce un seul serveur DNS et n'attrape donc
  que l'UDP/53 ; ce qui n'y passe pas par Tor est abandonné, jamais relayé en
  clair. Le manifeste signé ne sert qu'à sa liste d'adresses : l'App Store est
  le seul canal de mise à jour, aucune clé n'est sur l'appareil.
- **Obstacle** : `cargo check --target aarch64-apple-ios` échoue ici — `ring`
  compile du C et exige `xcrun` et le SDK iOS. La cible Rust s'installe, la
  compilation non. Deux pièges du vérificateur, déjà connus de la mission 25 :
  `cargo test | grep -q` tue cargo par SIGPIPE, et `nm | grep -q` fait de même ;
  les deux sorties sont désormais capturées avant filtrage.
- **Preuve** `scripts/verifier-m26.sh` : 6 tests du crate partagé et 6 du pont
  C verts sur l'hôte ; 9 fonctions C déclarées dans l'en-tête, exportées et
  liées dans `libtordns_ios.a` ; plists et entitements lus, tunnel de paquets
  conforme, aucun `dns-proxy` ; `project.yml` en YAML valide dont le chemin
  Rust correspond au script ; Swift n'appelle que l'ABI déclarée ; non-
  régression Android (APK arm64 reconstruit, quatre symboles JNI exportés) ;
  `actionlint` vert sur `ci.yml` ; aucune clé ni adresse `.onion` réelle.
  `code=0`. `scripts/ci/lint.sh` et `scripts/verifier-m25.sh` rejoués verts
  après le déplacement du crate.
- **Non prouvé** : compilation Swift, projet `xcodegen`, extension et tests
  simulateur (aucun macOS ici) ; archive signée, TestFlight et exécution du
  job `ios` ; mémoire réelle d'Arti dans l'extension (limite iOS ≈ 50 Mo) et
  éventuel déplacement d'Arti dans l'application ; activation du tunnel sur un
  appareil réel ; sortie du DNS en TCP/53, non traitée.
- **Demandé à qui** : à Claude, avec un Mac, lancer
  `scripts/ci/client-ios.sh`, corriger ce que la compilation Swift révélera et
  mesurer la mémoire de l'extension ; à Gary, l'équipe Apple, l'ouverture des
  capacités Network Extensions et le choix de publier ou non sur l'App Store.
