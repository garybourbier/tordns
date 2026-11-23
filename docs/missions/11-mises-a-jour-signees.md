# Mission 11 — Mises à jour signées : nœuds et client Linux

But : publier une version = une commande chez Gary ; les nœuds (cœur et bénévoles) et le
client Linux s'y mettent seuls, sans jamais accepter un fichier non signé ou plus ancien.

## À livrer

- `outils/publier/` (Go, sans dépendance réseau) :
  - `tordns-signer cle` : crée la paire Ed25519 de publication **dans un dossier choisi par
    Gary** (jamais dans le dépôt) ;
  - `tordns-signer manifeste` : construit `manifeste.json` (format dans `chantier-2-cadrage.md` :
    version entière croissante, expiration, cibles avec URL / taille / SHA-256, empreintes des
    images Docker des nœuds, liste des adresses cœur et communauté) et `manifeste.json.sig` ;
  - `tordns-signer verifier` : contrôle hors ligne.
- Clé publique de publication épinglée dans le code (constante), avec une procédure écrite
  de rotation (nouveau manifeste signé par l'ancienne clé qui annonce la nouvelle).
- **Mise à jour des nœuds** : un service `tordns-maj` (timer systemd, toutes les 6 h avec
  décalage aléatoire) qui récupère le manifeste par Tor, vérifie, puis `docker compose pull`
  **par empreinte** (`image@sha256:…`, jamais par étiquette) et relance ; retour à la
  version précédente si la sonde de santé échoue après relance.
- **Mise à jour du client Linux** : même vérification, remplacement atomique du binaire
  (écriture à côté puis `rename`), redémarrage du service systemd, retour arrière si le
  service ne repart pas.
- Miroir : chaque nœud sert le dernier manifeste et les fichiers sous `/maj/` ; GitHub
  Releases en secours.

## Refus obligatoires (chacun avec son test)

Signature fausse ; version ≤ version installée ; manifeste expiré ; taille ou SHA-256
différents ; image demandée par étiquette au lieu d'une empreinte.

## Preuve (`scripts/verifier-m11.sh`)

Clé jetable créée par le test : publication v2 → nœud et client passent en v2 ; v1 rejouée →
refusée ; manifeste altéré d'un octet → refusé ; image cassée → retour arrière automatique.
