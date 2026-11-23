# Mission 15 — Client macOS (Intel et Apple Silicon)

But : un client macOS équivalent au client Linux : relais DNS local vers le service caché
par Tor, réglage du DNS système, mise à jour signée.

## À livrer

- Réutiliser le code Go de `client-linux/` (le relais, le cache, DNSSEC, la liste
  d'adresses signée sont portables) : séparer ce qui est propre à Linux dans des fichiers
  `_linux.go` et ajouter les équivalents `_darwin.go`. Ne pas dupliquer le cœur.
- Ce qui change sur macOS :
  - service `launchd` (`/Library/LaunchDaemons/org.tordns.client.plist`) au lieu de systemd ;
  - réglage DNS par `networksetup -setdnsservers <service> 127.0.0.1` pour chaque service
    réseau actif, **valeurs d'origine sauvegardées et restaurées** à la désinstallation et à
    l'arrêt propre ; le diagnostic lit `scutil --dns` au lieu de `resolv.conf` ;
  - Tor : `tor` local en SOCKS comme sur Linux (documenter l'installation par Homebrew),
    le client refuse de démarrer si le SOCKS n'est pas joignable, sans jamais retomber en
    DNS clair ;
  - mise à jour : même manifeste, cible `client-macos` (binaire universel), remplacement
    atomique et `launchctl kickstart -k`, retour arrière comme sur Linux ; état dans
    `/Library/Application Support/TorDNS/` en `root:wheel 0700`.
- Construction : `scripts/ci/client-macos.sh` produit `amd64` et `arm64` puis un binaire
  **universel** (`lipo`, ou à défaut deux binaires si `lipo` est absent hors macOS) et un
  `.pkg` (`pkgbuild`/`productbuild` sur macOS ; sur Linux, produire seulement les binaires).
  Job `macos-latest` (Apple Silicon) et `macos-13` (Intel) ajouté à `ci.yml`.
- Signature Apple : **optionnelle**. Si les secrets `APPLE_DEVELOPER_ID_P12`,
  `APPLE_DEVELOPER_ID_MDP` et `APPLE_NOTARY_*` existent, signer et notariser ; sinon livrer
  un `.pkg` non signé et documenter « clic droit → Ouvrir ». Aucune valeur de ces secrets
  dans le dépôt, aucun `echo` de secret dans les journaux.
- `client-macos/README.md` : installation, réglage DNS, désinstallation, limites.

## Preuve (`scripts/verifier-m15.sh`)

Ici (Linux) : `GOOS=darwin GOARCH=amd64` et `arm64` compilent ; tests Go du code commun
verts ; tests unitaires de la partie darwin qui n'appellent pas le système (analyse de la
sortie de `scutil --dns` et de `networksetup -listallnetworkservices` sur des fixtures,
sauvegarde/restauration des DNS d'origine). NON PROUVÉ attendu : lancement réel sur un Mac,
`.pkg`, notarisation (premier push, runner macOS).
