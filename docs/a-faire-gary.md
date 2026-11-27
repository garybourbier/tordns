# Ce qui attend Gary

Liste unique des actions qui ne peuvent pas être faites depuis la machine de
développement : elles demandent un compte, du matériel, un secret ou un acte de
publication. Le détail et les preuves déjà obtenues sont dans
`docs/missions/journal.md` ; ce fichier ne contient que le reste à faire.

Règle inchangée : aucun secret dans le dépôt, et rien n'est poussé ni publié par
un agent. Chaque ligne indique la preuve attendue quand elle existe.

## 1. Publication de la 0.8.0

Tout le reste est prêt (`noeud/VERSION` = 0.8.0, section du CHANGELOG,
`docs/checklist-release-0.8.0.md`), mais aucun tag n'existe : rien n'est
téléchargeable aujourd'hui.

- pousser `master`, puis le tag `v0.8.0` ;
- contrôler la release brouillon, les `SHA256SUMS`, les attestations et les
  images GHCR multi-arch ;
- signer les APK et construire/signer le manifeste depuis la release brouillon,
  puis publier ;
- activer GitHub Pages avec la source « GitHub Actions ».

Preuve attendue : URL de la release, `SHA256SUMS` vérifié sur un fichier
téléchargé, page Pages en ligne.

## 2. Matériel et systèmes réels

- **Windows 11 (VM ou machine)** : `installer.exe`, tâche planifiée, droits de
  `maj\`, service, validation DNSSEC. Preuve : journal d'installation et
  `tordns --diagnostic`.
- **Appareil Android** : DNS privé activé puis désactivé, session
  d'installation, DNSSEC. Preuve : capture du diagnostic et verdict DNSSEC.
- **Mac Intel et Mac Apple Silicon** : lancement du client, `.pkg`, signature
  Developer ID et notarisation ; côté iOS, équipe Apple et capacités Network
  Extensions. Preuve : `spctl --assess` et lancement réel.
- **Routeur OpenWrt** (ramips/mt7621 ou mediatek/filogic) : flash, RAM, Tor,
  anti-fuite LAN. Preuve : sortie de `verifier-m23.sh` sur le routeur.
- **Carte SD Raspberry Pi** : premier démarrage complet. Preuve : journal série.
- **`makensis`** (paquet `nsis`, absent des dépôts de cette machine) : rejouer
  les étapes NSIS de `verifier-m14.sh` et `verifier-m21.sh`.

## 3. Serveurs et comptes

- **VPS Debian 12/13 vierge** : `noeud/installer.sh`, apt, systemd, puis
  registre/contrôleur avec Tor et PROXY v2. Preuve : `systemctl status` et une
  inscription réelle.
- **Deux VPS distincts** : perte d'un site réel, bascule Onionbalance, et une
  restauration `age` hors ligne.
- **GHCR** : premier envoi d'images multi-arch et empreintes réelles dans
  `images.txt`.
- **Variables de dépôt** de la page d'état du réseau, puis un passage du
  workflow Pages avec Tor.
- **Workflow Fuzz** lancé une fois à la main, corpus conservés s'ils grossissent.

## 4. Tiers

- **F-Droid** : ouvrir la demande sur `fdroiddata` (MR avec
  `metadata/org.tordns.client.yml` et `fastlane/`). `UpdateCheckMode: Tags`
  attend le tag `v0.8.0`.
- **OTF** : relire `docs/securite/demande-otf.md`, y mettre la date et le commit
  (`git rev-parse HEAD`), puis déposer la demande.
- **Zones réelles** : essayer le client contre quelques zones signées NSEC et
  NSEC3, et vérifier DNSSEC contre la racine réelle côté Windows et Android.
  Preuve : les trois verdicts du diagnostic (accepté, zone non signée, refusé).

## 5. Décision de modèle de confiance

La rotation d'ancre racine (KSK-2017 révoquée le 11/01/2027, retirée le
22/03/2027) n'est aujourd'hui livrable que par une release signée : le manifeste
ne transporte aucune ancre. Ajouter un champ d'ancre au manifeste change ce que
les clients considèrent comme racine de confiance : c'est une décision de Gary,
pas un correctif. Voir `docs/calendrier-racine.md`.
