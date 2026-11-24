# Périmètre de l'audit

## Version à auditer

- Version logicielle : `0.8.0` (`noeud/VERSION`, `site/telechargements.json`).
- Commit : le commit `master` figé au moment de la demande, à remplacer ici
  (`git rev-parse HEAD`) et à joindre à la demande OTF. Aucun audit ne doit
  porter sur du code non figé.
- Tout est dans un seul dépôt : <https://github.com/garybourbier/tordns>.

## Composants dans le périmètre

| Composant | Chemin | Langage |
|---|---|---|
| Relais DNS client (DoH par Tor, DNSSEC, cache, adresses signées) | `client-linux/relais/` | Go |
| Client Linux (service, diagnostic de fuites, mises à jour) | `client-linux/` | Go |
| Bibliothèque et outil de manifeste signé | `outils/manifeste/`, `outils/publier/` | Go |
| Appliqueur de mise à jour du nœud | `noeud/maj/` | Go |
| Nœud (Tor, Caddy, page d'état, installeur, compose) | `noeud/` | sh, Docker |
| Registre et admission des bénévoles | `controleur/registre/` | Go |
| Contrôleur et Onionbalance | `controleur/` | Docker, sh |
| Client Android (VPN, DNS privé, Arti) | `client-android/` | Kotlin, Rust |
| Client macOS | `client-macos/` | Go, sh |
| Client Windows | `client-windows/` | Rust |
| Paquet OpenWrt (procd, UCI, nftables, LuCI) | `client-openwrt/` | sh, JS |
| Publication (CI, release, reproduction) | `.github/workflows/`, `scripts/ci/` | YAML, sh, Python |

Priorité suggérée à l'auditeur : **relais et DNSSEC**, **format du manifeste
et chaîne de mise à jour**, **registre et admission**, puis clients
spécifiques (Android/Windows/macOS/OpenWrt).

## Environnement de test

Tout se rejoue sans serveur de production :

- `./scripts/ci/lint.sh` : actionlint, shellcheck, gofmt, go vet, cargo fmt.
- `./scripts/verifier-mNN.sh` : une preuve par mission, chacune listant ses
  « NON PROUVÉ ». Les plus utiles à l'auditeur :
  - `scripts/verifier-m11.sh` : manifeste signé, rejeu, retour arrière ;
  - `scripts/verifier-m13.sh` : cache, fuites, paquets hostiles, fuzzing ;
  - `scripts/verifier-m20.sh` : fuzzing long de l'analyse DNS ;
  - `scripts/verifier-m10.sh` : admission et éviction d'un bénévole menteur ;
  - `scripts/verifier-m23.sh` : image OpenWrt réelle dans QEMU, anti-fuite.
- `./scripts/ci/reproduire.sh` : reconstruction et comparaison octet à octet.
- Aucun test ne contient d'adresse `.onion` réelle, de clé de production ni de
  secret : les fixtures sont générées à la volée (`docs/missions/journal.md`,
  missions 11, 13, 19).

## Hors périmètre

- Tor lui-même, Docker, le noyau Linux, OpenWrt, Raspberry Pi OS.
- Les services de Gary (VPS, GHCR, GitHub Pages) au-delà de leur configuration
  décrite dans le dépôt.
- Les applications tierces qui utilisent TorDNS comme résolveur.
- L'ingénierie sociale et la sécurité physique.

## Questions précises pour l'auditeur

1. **Relais et DNSSEC** : la validation maison
   (`client-linux/relais/dnssec.go`) couvre-t-elle correctement les cas
   CNAME/DNAME, les zones non signées, les TTL négatifs et les réponses
   tronquées (TC) ? Le parseur résiste-t-il à des paquets hostiles
   (`client-linux/relais/hostiles_test.go`, `fuzz_test.go`) ?
2. **Manifeste et mises à jour** : le format (`outils/manifeste`) permet-il un
   rejeu, un retour arrière forcé, une confusion de version ou d'architecture ?
   Le remplacement atomique du binaire et le retour arrière
   (`client-linux/cmd/maj`, `noeud/maj`) laissent-ils une fenêtre exploitable ?
3. **Registre** : les limites par circuit et par jour, l'usage du PROXY v2 et
   la vérification du défi (`controleur/registre/proxyproto.go`,
   `controleur/registre/http.go`) résistent-ils à un bénévole malveillant qui
   forge l'en-tête ou rejoue une inscription ?
4. **Sondes** : un bénévole peut-il deviner les domaines sondés, ou faire
   mentir la comparaison A/RCODE/AD ?
5. **Onionbalance et PoW** : la configuration
   (`controleur/onionbalance`, `noeud/tor/Dockerfile`) expose-t-elle
   suffisamment la PoW et la rotation des descripteurs ?
6. **Clients** : les contournements de VPN Android et le plan DNS macOS
   (`client-android/app`, `client-macos/dns_plan.go`) fuient-ils dans les cas
   limites (réseau changeant, IPv6, DoH navigateur) ?
7. **OpenWrt** : la chaîne nftables
   (`client-openwrt/files/etc/tordns/anti-fuite.nft.template`) peut-elle être
   contournée (IPv6, DoH sur 443, résolveur local de l'appareil) ?
8. **Chaîne de publication** : un attaquant capable de pousser sur `master`
   peut-il publier un artefact sans signature, ou modifier les workflows pour
   exfiltrer un secret ?

## Livrables attendus de l'audit

Rapport avec gravité, scénario d'exploitation, correctif suggéré, et test de
non-régression à ajouter à `scripts/`. Les constats sont ensuite consignés dans
`docs/missions/journal.md` et, s'ils sont publics, dans `SECURITY.md`.
