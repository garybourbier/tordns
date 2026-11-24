# Client TorDNS pour iOS

Application SwiftUI + extension réseau qui achemine tout le DNS de l'appareil
par un circuit Tor, vers le service caché TorDNS. Aucune requête ne part en
clair : une requête qui ne peut pas passer par Tor est abandonnée.

> **État : écrit, non compilé.** Aucune chaîne Apple n'existe sur la machine de
> ce dépôt (ni `xcodegen`, ni `xcodebuild`, ni SDK iOS). Le crate Rust partagé
> et son pont C sont testés en local ; le Swift, le projet Xcode et le job CI
> `ios` ne le sont pas. Voir « Ce qui reste à prouver ».

## Pourquoi un tunnel de paquets et pas le proxy DNS

`NEDNSProxyProvider` est le mécanisme naturel pour intercepter le DNS, mais la
documentation Apple le réserve aux **appareils supervisés** : TN3134
(« Deploying a DNS proxy provider ») indique « app extension, iOS 11.0,
supervised devices only », et depuis iOS 15 le profil `com.apple.dnsProxy.managed`
doit être installé par un MDM. Une application grand public ne peut donc pas
l'activer : elle s'installerait sans jamais servir.

Le client utilise donc un `NEPacketTunnelProvider` **limité au DNS** :

- il annonce un unique serveur DNS, `10.255.0.1`, avec `matchDomains = [""]` ;
- il n'inclut **aucune route** (`includedRoutes = []`) : le trafic IP des
  applications continue de sortir par le réseau normal ;
- seules les requêtes vers ce serveur entrent dans le tunnel, sont converties
  en DoH et envoyées au `.onion` par Tor.

Limite assumée : seul l'UDP/53 est traité. Une application qui force le DNS
sur TCP/53 tombe en échec (elle retente en UDP) ; rien n'est relayé en clair.

## Ce que contient le dépôt

| Chemin | Rôle |
|---|---|
| `rust/` | pont C (`libtordns_ios.a`) sur le crate partagé `outils/arti-rust` |
| `rust/include/tordns.h` | ABI C consommée par Swift (en-tête de pont) |
| `Sources/Partage/` | réglages (App Group), paquets DNS, pont Swift vers Rust |
| `Sources/App/` | interface : marche/arrêt, adresses, DNSSEC, test de fuite, mémoire |
| `Sources/Extension/` | `NEPacketTunnelProvider` : lecture des paquets, DoH, réponse |
| `Config/` | Info.plist, entitements (`packet-tunnel-provider`), export TestFlight |
| `Tests/` | analyse des paquets DNS (simulateur, sans réseau) |
| `project.yml` | projet Xcode engendré par `xcodegen` (aucun `.xcodeproj` versionné) |

## Compiler

Sur un Mac avec Xcode 15 ou plus récent :

```sh
brew install xcodegen
cd client-ios
xcodegen generate
xcodebuild -project TorDNS.xcodeproj -scheme TorDNS \
  -destination 'platform=iOS Simulator,name=iPhone 16' CODE_SIGNING_ALLOWED=NO build
xcodebuild -project TorDNS.xcodeproj -scheme TorDNS \
  -destination 'platform=iOS Simulator,name=iPhone 16' CODE_SIGNING_ALLOWED=NO test
```

La cible `TorDNSTests` exécute les tests de `Sources/Partage/PaquetDNS.swift` :
analyse d'un paquet IPv4/UDP, refus des autres ports et protocoles, réponse
avec adresses et ports inversés, somme de contrôle d'en-tête.

Sur un appareil, il faut une équipe Apple (`TORDNS_TEAM_ID`), l'ouverture de la
capacité **Network Extensions → Packet Tunnel** pour les deux identifiants, et
le groupe d'applications `group.org.tordns.client`. La CI
(`scripts/ci/client-ios.sh`) saute l'archive signée et l'envoi TestFlight quand
ces secrets sont absents.

## Mises à jour et adresses

L'application est distribuée par l'App Store : aucune mise à jour n'est
installée hors de ce canal, et **aucune clé de signature n'existe sur
l'appareil**. Le manifeste signé ne sert qu'à sa liste d'adresses :

1. téléchargement de `/maj/manifeste.json` et `.sig` par Tor ;
2. vérification Ed25519 avec la clé publique épinglée dans le binaire
   (`tordns_verifier_manifeste`, crate `outils/manifeste-rust` partagé avec
   Android et Windows) ;
3. enregistrement des adresses `coeur`, `secours` et `communaute` du manifeste.

Un manifeste refusé ne remplace aucune adresse.

## Mémoire de l'extension

iOS accorde environ 50 Mo à une extension réseau. `Diagnostic.memoire()`
(`Sources/App/Diagnostic.swift`) lit `phys_footprint` par `task_info`. La
mesure doit être prise **dans l'extension** après le bootstrap Tor (Arti tient
des circuits, un magasin de consensus et SQLite en mémoire). Si la consommation
dépasse la limite, Arti doit tourner dans l'application et l'extension lui
parler en local : ce choix n'est pas tranché ici, faute de mesure.

## Ce qui reste à prouver

- compilation Swift, projet `xcodegen`, extension et tests : **jamais exécutés**
  (aucun macOS dans ce dépôt) ;
- `cargo build --target aarch64-apple-ios` : échoue ici, `ring` exige `xcrun`
  et le SDK iOS (`error occurred in cc-rs: failed to find tool "xcrun"`) ;
- mémoire réelle d'Arti dans l'extension, et tenue du tunnel sous 50 Mo ;
- activation du tunnel sur un appareil réel (autorisation VPN, App Group) ;
- comportement d'iOS quand Tor met 20 à 90 s à démarrer : le tunnel démarre
  avant la fin du bootstrap, les requêtes arrivées trop tôt sont abandonnées ;
- envoi TestFlight et validation App Store.
