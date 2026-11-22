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
