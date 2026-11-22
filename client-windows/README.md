# TorDNS — client Windows (Mission 6)

Service Windows qui capture le DNS de la machine via un adaptateur **WinTun**
et le résout en DoH vers le `.onion` de TorDNS à travers un proxy Tor local
(SOCKS5). Aucun paquet DNS n'est émis en clair ; seuls les noms de statut sont
journalisés, jamais les domaines.

```
Applications Windows / résolveur système
   │ UDP 53 vers 10.111.222.1
   ▼
Adaptateur WinTun « TorDNS » (10.111.222.2/32)
   │ lecture des paquets par le service
   ▼
tordns-client (service LocalSystem/administrateur)
   │ cache LRU + POST DoH keep-alive par requête
   ▼
SOCKS5 127.0.0.1:9050 (Tor) ──► <adresse>.onion ──► Caddy → passerelle → Unbound
```

Contrairement au client Android, Tor n'est pas embarqué : le service suppose un
démon Tor (ou Tor Browser / Tor Expert Bundle) exposant un `SocksPort` local.
C'est le même modèle que le client Linux de la Mission 4.

## Composants

| Fichier | Rôle |
|---|---|
| `src/main.rs` | service, mode console, `--verifier-config`, aide |
| `src/service.rs` | enregistrement SCM, arrêt propre |
| `src/wintun.rs` | chargement dynamique de `wintun.dll`, configuration netsh, boucle DNS |
| `src/resolveur.rs` | cache puis DoH, statistiques |
| `src/dns.rs` | noms compressés, clé, bit DO, TTL, SERVFAIL |
| `src/paquet.rs` | IPv4/UDP, sommes IP et UDP |
| `src/doh.rs` | SOCKS5 (ATYP 3) puis HTTP/1.1 `POST /dns-query` |
| `src/config.rs` | `client.conf` en `clé = valeur` |
| `installateur/tordns.nsi` | installateur NSIS + service `sc create` |

## Configuration

`C:\ProgramData\TorDNS\client.conf` (créé vide par l'installateur) :

```ini
onion = <adresse>.onion
socks = 127.0.0.1:9050
tun = TorDNS
cache = 4096
anti_fuite = non
ttl_max = 3600
delai = 15
```

- `anti_fuite = oui` ajoute `DisableSmartNameResolution` et
  `DisableSmartMultiHomedNameResolution` sous
  `HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters`, pour empêcher
  Windows d'interroger en parallèle les résolveurs des autres interfaces.
- Le service exige les droits administrateur (création d'adaptateur, netsh,
  registre).
- Au premier démarrage, `netsh` affecte `10.111.222.2/32` à l'adaptateur,
  `10.111.222.1` comme DNS et ajoute la route `10.111.222.1/32`.

## Construction (depuis Linux)

```bash
rustup target add x86_64-pc-windows-gnu
# MinGW : x86_64-w64-mingw32-gcc
cd client-windows
./scripts/construire.sh          # tests + exe dans dist/ (+ NSIS si makensis)
```

Le script exécute `cargo test`, compile pour `x86_64-pc-windows-gnu`, copie
`tordns-client.exe` dans `dist/`, puis appelle `makensis` s'il est installé.
`wintun.dll` n'est **pas** versionnée : téléchargez-la depuis la distribution
officielle de WireGuard/WinTun et placez-la dans `dist/` (ou à côté de l'exe,
ou dans `System32`).

## Installation sur Windows

1. Copier `tordns-client.exe` et `wintun.dll` dans `C:\Program Files\TorDNS\`.
2. Renseigner `C:\ProgramData\TorDNS\client.conf`.
3. En administrateur :
   ```bat
   sc create TorDNS binPath= "C:\Program Files\TorDNS\tordns-client.exe" start= demand DisplayName= "TorDNS"
   sc start TorDNS
   ```
   (ou lancer `TorDNS-0.1.0-setup.exe` généré par NSIS).
4. Contrôle : `nslookup example.com 10.111.222.1`, puis `ping example.com`.
5. Désinstallation : `sc stop TorDNS && sc delete TorDNS`, puis supprimer le
   dossier et, si nécessaire, l'adaptateur WinTun dans le gestionnaire de
   périphériques.

## Signature de l'installateur

Aucun certificat de signature n'est disponible dans ce dépôt ; l'installateur
produit n'est donc pas signé. Sur une machine disposant d'un certificat
Authenticode :

```bat
signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /a ^
  TorDNS-0.1.0-setup.exe
```

## Preuves exécutées ici

Environnement Linux, sans Windows ni pilote WinTun :

```text
$ cargo test
test result: ok. 18 passed; 0 failed
```

Couvre : nom/clé DNS, bit DO, compression, TTL 300 → 298 → plancher 1 s,
SERVFAIL, cache LRU/expiration/TTL nul, extraction et réinjection IPv4/UDP avec
sommes IP **et** UDP valides, configuration (erreurs, doublons, booléens), et un
échange DoH complet contre un faux proxy SOCKS5 local (poignée de main, CONNECT
ATYP 3, POST `/dns-query`, `Content-Length`).

Cross-compilation et exécution sous Wine :

```text
$ cargo build --release --target x86_64-pc-windows-gnu
Finished release ... (tordns-client.exe, 1 474 063 octets)

$ wine tordns-client.exe --version
tordns-client 0.1.0

$ wine tordns-client.exe --verifier-config Z:\tmp\tordns-win.conf
configuration valide : tunnel=TorDNS, socks=127.0.0.1:9050, cache=64, anti_fuite=true

$ wine tordns-client.exe --console Z:\tmp\tordns-win.conf
erreur : wintun.dll introuvable (placez-la à côté de l'exécutable ou dans System32)
```

Le dernier message est le comportement attendu sans pilote : le binaire démarre,
résout les symboles WinTun à l'exécution et échoue proprement.

## Non vérifié ici, et pourquoi

- **Exécution réelle du service et de l'adaptateur WinTun** : nécessite Windows,
  les droits admin et le pilote signé. Wine ne charge pas WinTun.
- **Installateur NSIS** : `makensis` n'est pas installé sur cette machine ; le
  script est fourni mais n'a pas été compilé.
- **Signature Authenticode** : aucun certificat disponible.

## Limites connues

- **DNS sur TCP et IPv6** non capturés (comme le client Android) ; seules les
  requêtes UDP IPv4 vers le port 53 sont traitées.
- **Anti-fuite partiel** : les applications configurées avec leur propre DoH/DoT
  échappent au tunnel ; le réglage registre réduit les fuites multi-interfaces
  mais ne bloque pas tout.
- Une requête DoH par requête DNS manquante (pas de keep-alive) ; le cache LRU
  absorbe les répétitions.
- L'état Tor n'est pas géré : si le proxy SOCKS tombe, les requêtes reçoivent
  un SERVFAIL (les clients retentent).
- Aucun journal de domaine ; le journal se limite au démarrage, aux erreurs
  d'infrastructure et au bilan d'arrêt.
