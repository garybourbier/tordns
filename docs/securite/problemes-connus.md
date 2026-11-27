# Problèmes connus et preuves manquantes

Regroupement de tout ce que `docs/missions/journal.md` marque « NON PROUVÉ »
ou « reste », classé par gravité. Rien n'est ajouté ici qui ne soit écrit au
journal ; la référence entre parenthèses renvoie à l'entrée du journal.

## Gravité haute — vie privée

- **Un nœud bénévole voit les noms demandés.** C'est structurel : le `.onion`
  termine le chiffrement. Défenses : aucun journal de requête côté nœud,
  DNSSEC, éviction des menteurs. Preuve partielle seulement — l'absence de nom
  dans les journaux est testée (`scripts/verifier-m07.sh`), pas l'honnêteté
  d'un opérateur qui lit la mémoire. (journal, mission 7)
- **La PoW derrière Onionbalance n'est pas mesurée.** On ne sait pas si elle
  protège réellement les nœuds cœur d'un déluge, ni son coût sur un Pi.
  (journal, mission 7)
- **DNSSEC ne couvre pas les zones non signées** : pour elles, un nœud
  malveillant peut forger une réponse. Le repli est explicite et documenté,
  mais non détectable par l'utilisateur au-delà de l'état affiché.
  (`client-linux/relais/dnssec.go`, journal, mission 12)
- **Le transport Tor réel n'est pas prouvé dans les tests** : le registre, les
  mises à jour et l'état réseau sont testés en HTTP local ou avec des sondes
  simulées. L'émission effective du PROXY v2 par Tor n'a pas été observée.
  (journal, missions 10, 11, 22)
- **Aucun test sur un vrai réseau censuré** : blocage de Tor, ports filtrés,
  portails captifs ne sont pas couverts. (journal, mission 19)

## Gravité haute — intégrité et chaîne de publication

- **La CI et la release n'ont jamais tourné sur un tag réel** : workflows
  écrits et relus, mais non exécutés ; les empreintes des images de base et de
  Go/Rust restent à confirmer au premier passage. (journal, missions 16, 21)
- **Les runners ARM de GitHub ne sont pas disponibles** pour la preuve locale ;
  l'exécution sur `ubuntu-24.04-arm` n'est pas constatée. (journal, mission 14)
- **La rotation de la clé de manifeste sur un parc réel** n'a pas été faite ;
  seul le format et les refus sont testés. (journal, mission 11)
- **Le tirage d'images par empreinte contre un vrai registre** (GHCR) n'a pas
  été exécuté ; les tests utilisent un registre local et un `docker` factice.
  (journal, mission 11)
- **La construction de `tordns-maj` par l'installeur sur un Debian vierge**
  n'est pas prouvée, faute de machine Debian jetable. (journal, mission 11)

## Gravité moyenne — déploiement

- **`noeud/installer.sh` n'a jamais installé Docker par `apt` ni activé
  systemd sur une machine vierge** : le bac à sable utilise le Docker de la
  machine de développement. (journal, mission 8)
- **Aucun nœud bénévole réel** : l'inscription, l'admission, l'éviction et le
  second descripteur Onionbalance sont testés avec un nœud factice.
  (journal, missions 9, 10)
- **Aucun VPS distant** : latence, charge et comportement réseau réels ne sont
  pas mesurés. (journal, missions 7, 8)
- **Le socket de statut d'Onionbalance réel** n'a pas été lu ; la date publiée
  est celle de la dernière **tentative**, pas une confirmation d'upload.
  (journal, mission 22)
- **Les paquets OpenWrt mips et arm ne sont pas installés** : seuls les
  binaires sont vérifiés par `file`, et le test système tourne sur x86_64.
  (journal, mission 23)
- **La page LuCI n'est ni construite ni affichée** ; sa syntaxe seule est
  vérifiée. (journal, mission 23)
- **Aucun vrai routeur** : flash, RAM réelle et Tor contraint à 256 Mo ne sont
  pas mesurés. (journal, mission 23)

## Gravité moyenne — clients spécifiques

- **Windows** : installation réelle, redémarrage et ACL NTFS non prouvés hors
  Windows (Wine n'a pas d'ACL NTFS). (journal, missions 12 et 13)
- **Windows, NSEC3** : hickory 0.24 ne valide que les preuves NSEC. Un
  NXDOMAIN ou un NODATA dans une zone signée en NSEC3 est refusé (SERVFAIL),
  et une zone non signée déléguée par un parent NSEC3 aussi : la preuve
  d'absence de DS n'arrive jamais. C'est conservateur, mais une partie des
  zones de l'Internet utilise NSEC3 ; aucun nom n'est mal résolu, ces réponses
  échouent. Le refus est figé par les tests `nxdomain_nsec3_seul_refuse` et
  `zone_non_signee_sous_parent_nsec3_refusee`
  (`client-windows/src/dnssec.rs`). (journal, mission 28)
- **Windows, zone non signée réelle** : l'acceptation prouvée par NSEC est
  testée hors ligne ; elle n'a pas encore été exercée contre une vraie racine
  (`google.com` par exemple). (journal, mission 28)
- **macOS** : lancement réel, `launchd`, paquet `.pkg`, signature Developer ID
  et notarisation non prouvés. (journal, missions 15, 21)
- **Android** : l'APK n'est pas signé par une clé de production dans les
  tests, et le comportement VPN sur appareil réel n'est pas mesuré.
  (journal, mission 12)
- **OpenWrt** : l'anti-fuite ne couvre ni DoH sur 443, ni IPv6, ni un
  résolveur local de l'appareil ; c'est un choix documenté
  (`client-openwrt/README.md`), pas une garantie, et le rendu nftables n'est
  mesuré que sur x86_64 (journal, mission 23).

## Faible — divers

- **Reproducibilité macOS, images multi-arch et Windows** : non vérifiée hors
  Linux ; `reproduire.sh` n'a pas tourné sur un tag. (journal, mission 21)
- **Le rendu réel du README et des badges GitHub** n'est pas testé.
  (journal, mission 18)
- **La page du site en ligne** dépend d'une activation manuelle de Pages.
  (journal, mission 17)
- **La durée réelle du fuzzing dans GitHub Actions** (10 min par cible) n'est
  pas constatée. (journal, mission 20)
- **Les fixtures DNS sont générées en mémoire** : aucun échange avec un vrai
  résolveur récursif. (journal, mission 13)

## Risques acceptés

- Un bénévole peut journaliser ce qu'il reçoit : assumé et affiché sur le site,
  atténué par DNSSEC et l'éviction, jamais éliminé.
- Tor ne protège pas contre un nœud de sortie malveillant vis-à-vis de la
  disponibilité (coupure), seulement de la confidentialité.
- GitHub reste un point de confiance pour le code et la CI ; les signatures
  hors ligne en limitent l'impact.
