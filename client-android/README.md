# TorDNS — client Android (Mission 5)

Application Android sans root qui capture le DNS de l'appareil via `VpnService`
et le résout par DoH vers le `.onion` de TorDNS, avec **Arti** (implémentation
Tor officielle en Rust) embarqué.

```
Applications Android / résolveur système
   │ UDP 53 vers 10.111.222.1 (TUN, sans root)
   ▼
TorVpnService ── cache LRU mémoire (TTL décroissants)
   │ JNI (libtordns_arti.so)
   ▼
Arti (Rust) ── circuits Tor ──► <adresse>.onion:80 ──► Caddy → passerelle → Unbound
```

## Composants

| Fichier | Rôle |
|---|---|
| `app/.../MainActivity.java` | adresse `.onion`, choix du mode, activation VPN, test et compteurs |
| `app/.../TorVpnService.java` | tunnel TUN, lecture des paquets, notification, arrêt |
| `app/.../Paquet.java` | analyse IPv4/UDP et construction de la réponse (sommes comprises) |
| `app/.../DnsMessage.java` | noms compressés, clé de cache, bit DO, TTL, SERVFAIL |
| `app/.../DnsCache.java` | LRU borné, expiration, TTL décrémentés, TTL négatif du SOA |
| `app/.../Diagnostic.java` | détection du DNS privé Android (DoT) hors VpnService |
| `app/.../Resolveur.java` | bootstrap unique, pool DoH, statistiques |
| `app/.../Arti.java` | déclarations JNI |
| `rust/src/lib.rs` | `demarrer` / `doh` / `arreter`, POST HTTP/1.1 via `TorClient::connect` |

## Build

Prérequis : JDK 17, Android SDK (plateforme 34, build-tools 34), NDK 26,
Rust avec la cible `aarch64-linux-android`. Aucun Gradle : l'APK est assemblé
avec `aapt2`, `javac`, `d8`, `zipalign` et `apksigner`.

```bash
rustup target add aarch64-linux-android
cd client-android
./scripts/construire.sh        # → build/tordns-client.apk (arm64-v8a, signé debug)
./scripts/tester.sh            # tests hôte : DNS, cache, paquets
adb install -r build/tordns-client.apk
```

La clé de signature est celle de l'Android SDK (`~/.android/debug.keystore`),
jamais versionnée ; aucun secret ni adresse `.onion` ne figure dans le dépôt.

## Utilisation

1. Ouvrir TorDNS, saisir l'adresse `.onion` du service (conservée dans les
   préférences privées de l'application).
2. Choisir le mode :
   - **DNS du système uniquement** : le VPN n'annonce que `10.111.222.1` comme
     résolveur ; les applications utilisant le résolveur système sont capturées.
   - **Anti-fuite** : ajoute des routes vers huit résolveurs publics connus
     (8.8.8.8, 1.1.1.1, 9.9.9.9, OpenDNS…). Les requêtes DNS envoyées en dur y
     sont détournées ; les autres flux vers ces adresses (DoH, etc.) sont coupés.
3. « Activer la protection », accepter la demande VPN d'Android.
4. Le bandeau de diagnostic lit le réglage « DNS privé » : s'il est en mode
   automatique ou strict, Android envoie du DoT hors du VpnService ; l'écran
   indique la fuite et demande de le passer sur « Désactivé ».
5. « Résoudre via Tor » teste le chemin complet (même sans VPN) et affiche le
   code de réponse, le nombre d'enregistrements et la durée.
6. Les compteurs (requêtes, cache, erreurs) sont visibles en bas de l'écran.

L'application elle-même est **exclue du VPN** (`addDisallowedApplication`) :
Arti doit joindre le réseau Tor avec le résolveur système, sinon le bootstrap
dépendrait de la résolution qu'il fournit (interblocage). C'est la seule requête
DNS qui échappe au tunnel — et elle ne concerne que des nœuds d'entrée Tor.

## Preuves

**1. Chemin Arti complet sur l'hôte** (même code que le JNI, bibliothèque
`tordns_arti`) :

```bash
cd rust
cargo run --release --example doh -- <adresse>.onion example.com
# bootstrap Arti… Tor prêt, POST DoH vers <adresse>.onion
# réponse DoH : 61 octets, id 0x1234, rcode 0, réponses 2
```

**2. Briques DNS/cache/paquets** (`./scripts/tester.sh`) :

```
OK : 33 vérifications locales passées (dont 10 000 paquets hostiles)
```

Couvre : nom normalisé et clé (`example.com|1|1|plain`), bit DO de l'OPT,
extraction IPv4/UDP (ports, charge utile), échange d'adresses/ports et sommes
IP/UDP valides, réécriture d'identifiant, TTL 300 → 298 après 2 s, TTL positif
ignorant l'autorité, NXDOMAIN/NODATA par le SOA, TTL nul non caché, LRU borné,
SERVFAIL bien formé, diagnostic du DNS privé, et 10 000 paquets hostiles.

**3. APK et chargement JNI sur appareil** :

```
package: org.tordns.client  versionName=0.1  minSdk=26  targetSdk=34
native-code: 'arm64-v8a'
lib/arm64-v8a/libtordns_arti.so   7 688 656 octets
primaryCpuAbi=arm64-v8a
11-22 13:11:22 I TorDNS: bibliothèque Arti chargée
```

Installé et lancé sur un Samsung SM-A546B (Android 16, arm64) ; `zipalign -c -p 4`
passe, signature APK vérifiée.

**4. Chemin Arti/DoH complet sur l'appareil, sans VPN.** L'APK étant construit
en mode debug (`--debug-mode`), une intention de diagnostic réservée aux builds
débogables démarre le bootstrap puis une requête, même écran verrouillé :

```bash
adb shell am start -n org.tordns.client/.MainActivity \
  --ez diagnostic true --es onion <adresse>.onion
# I TorDNS: bootstrap : retour OK
# I TorDNS: diagnostic DoH sur l'appareil : rcode=0 reponses=2 apres 40004 ms
```

L'activité de diagnostic se déclare `showWhenLocked` : sans cela, Android gèle
le processus derrière l'écran de verrouillage et le bootstrap ne progresse
jamais. Aucun nom de domaine n'est journalisé, seul le code de réponse.

**5. Capture DNS réelle à travers le VPN.** Après déverrouillage de l'appareil
et activation depuis l'écran (le consentement VPN est obligatoire), le réseau
VPN est `tun0` avec `10.111.222.1` comme résolveur :

```text
VpnTransportInfo{type=1, sessionId=TorDNS, bypassable=false}
tun0  LinkAddresses: [10.111.222.2/32]  DnsAddresses: [10.111.222.1]
D NetdEventListenerService: DNS Requested by 1074, 2000(com.android.shell), SUCCESS, 4ms

$ adb shell ping -c 1 example.com
PING example.com (104.20.23.154) 64 bytes ... time=177 ms
$ adb shell ping -c 1 wikipedia.org   # 185.15.58.224, 345 ms
$ adb shell ping -c 1 debian.org      # 151.101.2.132, 238 ms

Requêtes : 73   cache : 23   erreurs : 0   entrées : 14
```

Les trois noms sont résolus par TorDNS (compteur en hausse, cache alimenté,
zéro erreur), puis les paquets ICMP sortent normalement par le réseau physique
(seul le DNS est routé vers le TUN). Le VPN a été désactivé après le test.

## Sécurité et limites

- **Zéro journal** : aucun nom de domaine n'est écrit (ni logcat, ni fichier).
  L'adresse `.onion` vit dans les préférences privées, l'état Tor dans
  `files/arti-etat` et le cache de répertoires dans `cache/arti-cache`.
- **Aucune résolution locale** : tout passe par le circuit Tor d'Arti ; aucune
  requête DNS en clair vers l'extérieur.
- **Cache volatil** : 512 entrées, expiration au TTL de la réponse (SOA pour
  NXDOMAIN/NODATA), plafond 1 h, non partagé, effacé à la mort du processus.
- **UDP seulement** : les requêtes DNS sur TCP (TCP/53) et les paquets IPv6 ne
  sont pas traités. Un client qui force TCP échoue et retombe généralement sur
  UDP. C'est le principal écart avec la Phase 4.
- **Anti-fuite partiel** : les applications qui font leur propre DoH/DoT vers un
  domaine (et non vers une IP connue) ne sont pas interceptées ; seul un VPN
  complet avec NAT le permettrait. Le DNS privé Android est détecté et signalé,
  pas désactivé à la place de l'utilisateur.
- **Arm64 uniquement** dans ce build ; `minSdk 26`. Une compilation x86_64 pour
  émulateur se fait en changeant la cible dans `scripts/construire.sh`.
- La notification de service permanent utilise le type `specialUse` (Android 14).
- Les requêtes DNS de type `ANY` reçoivent `NOTIMP` du serveur (Mission 3) : les
  applications qui n'essaient que ce type voient un délai d'attente, comme dans
  les journaux Android (`TIMEOUT`) observés pour deux applications.
- Le fichier natif est aligné sur 16 Kio (`max-page-size=16384`), exigence
  d'Android 16 pour les pages de 16 Kio.
- Le point d'entrée de diagnostic (`--ez diagnostic true`) est inactif hors APK
  débogable ; il ne sert qu'aux preuves locales sur appareil.
- Arti met 20 à 90 s à démarrer au premier lancement ; les requêtes reçues
  avant la fin du bootstrap reçoivent un SERVFAIL, que les clients retentent.

## Pistes

- DNS sur TCP et IPv6 dans le TUN.
- Pool de connexions HTTP keep-alive côté Rust (une connexion Tor par requête
  actuellement).
- Build Gradle/CI signé et ABI multiples, tests instrumentés du tunnel.
