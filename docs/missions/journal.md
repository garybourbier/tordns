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
