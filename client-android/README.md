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
| `app/.../DnsCache.java` | LRU borné, expiration, TTL décrémentés |
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
4. « Résoudre via Tor » teste le chemin complet (même sans VPN) et affiche le
   code de réponse, le nombre d'enregistrements et la durée.
5. Les compteurs (requêtes, cache, erreurs) sont visibles en bas de l'écran.

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
OK : 21 vérifications locales passées
```

Couvre : nom normalisé et clé (`example.com|1|1|plain`), bit DO de l'OPT,
extraction IPv4/UDP (ports, charge utile), échange d'adresses/ports et sommes
IP/UDP valides, réécriture d'identifiant, TTL 300 → 298 après 2 s, LRU borné,
SERVFAIL bien formé.

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

**Non vérifié ici** : l'activation effective du tunnel. L'appareil de test est
verrouillé par code et la boîte de consentement VPN exige une action de
l'utilisateur ; aucun contournement n'a été tenté. La capture TUN, elle, est
couverte par les tests de paquets et par la revue du service.

## Sécurité et limites

- **Zéro journal** : aucun nom de domaine n'est écrit (ni logcat, ni fichier).
  L'adresse `.onion` vit dans les préférences privées, l'état Tor dans
  `files/arti-etat` et le cache de répertoires dans `cache/arti-cache`.
- **Aucune résolution locale** : tout passe par le circuit Tor d'Arti ; aucune
  requête DNS en clair vers l'extérieur.
- **Cache volatil** : 512 entrées, TTL plafonné à 1 h, non partagé, effacé à la
  mort du processus.
- **UDP seulement** : les requêtes DNS sur TCP (TCP/53) et les paquets IPv6 ne
  sont pas traités. Un client qui force TCP échoue et retombe généralement sur
  UDP. C'est le principal écart avec la Phase 4.
- **Anti-fuite partiel** : les applications qui font leur propre DoH/DoT vers un
  domaine (et non vers une IP connue) ne sont pas interceptées ; seul un VPN
  complet avec NAT le permettrait.
- **Arm64 uniquement** dans ce build ; `minSdk 26`. Une compilation x86_64 pour
  émulateur se fait en changeant la cible dans `scripts/construire.sh`.
- La notification de service permanent utilise le type `specialUse` (Android 14).
- Arti met 20 à 90 s à démarrer au premier lancement ; les requêtes reçues
  avant la fin du bootstrap reçoivent un SERVFAIL, que les clients retentent.

## Pistes

- DNS sur TCP et IPv6 dans le TUN.
- Pool de connexions HTTP keep-alive côté Rust (une connexion Tor par requête
  actuellement).
- Build Gradle/CI signé et ABI multiples, tests instrumentés du tunnel.
