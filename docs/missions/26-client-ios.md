# Mission 26 — Client iOS

But : un client iPhone/iPad équivalent au client Android, avec Tor embarqué.

## À livrer

- Application SwiftUI + extension **Network Extension** de type `NEDNSProxyProvider` (ou
  `NEPacketTunnelProvider` limité au DNS si le proxy DNS exige une supervision : vérifier
  dans la documentation Apple et écrire le choix et sa raison).
- Tor embarqué : **Arti** compilé pour `aarch64-apple-ios` et `aarch64-apple-ios-sim`
  (xcframework), en réutilisant le code Rust de `client-android/rust` (DoH par Tor,
  DNSSEC, manifeste) — partager le crate plutôt que le copier.
- Contrainte mémoire des extensions réseau iOS (environ 50 Mo) : mesurer la mémoire d'Arti
  dans l'extension, la documenter, et si elle dépasse, faire tourner Arti dans l'app avec
  une communication locale, en le disant clairement.
- Interface : marche/arrêt, adresse cœur/secours/communauté, état DNSSEC, test de fuite.
- Mises à jour : par l'App Store (pas de manifeste), mais la **liste d'adresses signée**
  (manifeste) est bien lue et vérifiée comme sur Android.
- Projet Xcode généré par `xcodegen` (fichier `project.yml` versionné, pas de `.xcodeproj`
  à la main) ; job CI `macos-latest` qui compile pour le simulateur et lance les tests ;
  signature et envoi TestFlight **seulement** si les secrets Apple de Gary existent, étape
  sautée sinon.

## Preuve (`scripts/verifier-m26.sh`)

Ici (Linux) : le crate Rust partagé compile pour les cibles iOS si la chaîne est
installable (`rustup target add`), ses tests passent sur l'hôte ; `xcodegen` et le Swift ne
peuvent pas être lancés : NON PROUVÉ attendu (runner macOS au premier push, appareil réel
chez Gary).
