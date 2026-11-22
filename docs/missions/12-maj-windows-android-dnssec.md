# Mission 12 — Mises à jour Windows et Android, adresses signées, DNSSEC côté client

## Mises à jour

- **Windows** : le service vérifie le manifeste (même code de vérification que la mission 11,
  porté en Rust ou partagé), télécharge l'installateur NSIS par Tor, vérifie SHA-256 et
  signature, le lance en silencieux (`/S`), contrôle que le service repart ; sinon réinstalle
  la version précédente gardée en cache.
- **Android** : une app installée hors Play ne peut pas se remplacer sans l'accord de
  l'utilisateur. Faire : vérification du manifeste en arrière-plan, notification « mise à
  jour vérifiée disponible », installation par `PackageInstaller` (session) au toucher. Même
  clé de signature APK d'une version à l'autre (sinon Android refuse : l'écrire dans la doc de
  publication). Proposer en plus, dans la doc, un dépôt F-Droid servi par les nœuds.

## Liste d'adresses signée

Les clients ne codent plus l'adresse en dur : ils lisent la liste cœur / communauté du
dernier manifeste vérifié (une liste de secours est embarquée à la compilation). Réglage
utilisateur : « cœur seulement » (défaut), « cœur puis communauté en secours »,
« communauté ». L'écran dit en clair que les nœuds communauté sont des bénévoles non vérifiés.

## DNSSEC côté client

Option (activée par défaut si le coût est acceptable) : le client valide lui-même les
signatures DNSSEC des réponses (bibliothèque reconnue de chaque langage, pas de crypto
maison). Une réponse signée fausse est rejetée et le nœud est signalé au registre
(`POST /signalement`, sans rien sur l'utilisateur).

## Preuve (`scripts/verifier-m12.sh`)

Windows : sous Wine ou VM, passage v1 → v2 et refus d'un installateur altéré. Android : test
instrumenté ou émulateur, notification puis installation. DNSSEC : un nœud de test menteur
fait rejeter la réponse par les trois clients.
