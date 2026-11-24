# Modèle de menace

Ce document décrit ce que TorDNS protège, contre qui, et avec quel fichier et
quelle preuve. Il ne promet rien que le code ne fasse : chaque défense renvoie
au fichier qui l'implémente et au vérificateur qui la teste. Les limites sont
dans [problemes-connus.md](problemes-connus.md).

## Actifs

1. **Vie privée des requêtes** : quel nom de domaine un appareil demande, et
   quand. C'est l'actif principal : TorDNS existe pour qu'un FAI, un État ou un
   opérateur Wi-Fi ne puisse pas le lire.
2. **Intégrité des réponses** : l'adresse renvoyée doit être la vraie, pas une
   réponse forgée par un intermédiaire (attaque de l'homme du milieu).
3. **Clés `.onion` et de publication** : la clé du service caché du nœud, la
   clé Ed25519 qui signe le manifeste de mise à jour et des adresses, la clé de
   signature des paquets, les secrets Apple/Android de Gary.
4. **Disponibilité du réseau** : nœuds cœur et communauté joignables, registre
   capable d'admettre et d'évincer, mises à jour applicables.

## Adversaires et défenses

### 1. FAI, État censeur, opérateur réseau local

Il voit le trafic IP de la machine, peut bloquer Tor, injecter des réponses DNS
ou monter un portail captif.

- Le client n'interroge **que** le service caché, via le SOCKS local de Tor :
  `client-linux/relais/doh.go`, `client-linux/relais/relais.go`. Aucune
  résolution DNS système n'est faite pour le nom demandé.
- Le diagnostic refuse de laisser croire à une protection quand le système ou
  le navigateur utilise encore un résolveur en clair ou DoH :
  `client-linux/diagnostic.go` (code de sortie 1 s'il reste une fuite).
- Android exige que « DNS privé » soit désactivé et guide l'utilisateur ;
  Windows vérifie netsh et les politiques DoH : `client-windows/src`,
  `client-android/app`.
- OpenWrt bloque le DNS direct et DoT des appareils du LAN :
  `client-openwrt/files/etc/tordns/anti-fuite.nft.template`.
- Preuves : `scripts/verifier-m13.sh` (diagnostic), `scripts/verifier-m23.sh`
  (anti-fuite réelle dans une image OpenWrt sous QEMU).

### 2. Nœud bénévole malveillant ou curieux

Il reçoit les requêtes en clair après Tor (le `.onion` termine le chiffrement)
et peut journaliser, mentir ou renvoyer une adresse fausse.

- Le nœud ne journalise aucun nom : Caddy et les conteneurs sont configurés
  sans journal de requête (`noeud/docker-compose.yml`, `noeud/caddy`), et
  `scripts/verifier-m07.sh` vérifie l'absence de nom dans les journaux.
- Le client valide **DNSSEC** lui-même et refuse une réponse sans preuve
  quand la zone en publie : `client-linux/relais/dnssec.go`, avec repli
  explicite `--dnssec non` documenté.
- Le registre sonde les bénévoles à domaines tirés au hasard et compare A,
  RCODE et bit AD à sa propre résolution ; un menteur ou une fausse IP est
  évincé : `controleur/registre/dns.go`, `controleur/registre/registre.go`.
- Le pool communauté est distinct du cœur et n'est utilisé que si l'utilisateur
  choisit ce mode (`--mode-adresse communaute`).
- Preuves : `scripts/verifier-m10.sh` (menteur évincé), `scripts/verifier-m13.sh`
  (paquets hostiles, fuzzing `client-linux/relais/fuzz_test.go`).

### 3. Attaquant réseau sur Tor (relais de sortie, nœud de rendez-vous)

Il voit du trafic chiffré, peut retarder ou couper ; il ne lit pas les noms.

- Tor fait le transport ; TorDNS n'ajoute aucune métadonnée au `.onion`.
- Les adresses sont signées : le client refuse une liste d'adresses non signée,
  expirée ou rejouée : `client-linux/relais/adresses.go`, `outils/manifeste`.

### 4. Attaquant local sur le poste client

Il peut lire les fichiers de l'utilisateur, lancer un processus, modifier le
résolveur système.

- Le client n'écrit aucun nom de domaine sur disque ; le cache est en mémoire
  et borné (`client-linux/relais/cache.go`).
- Aucune clé privée n'est stockée côté client : le client ne fait que vérifier
  des signatures publiques.
- Les mises à jour sont vérifiées avant application (signature Ed25519,
  expiration, SHA-256, refus de rejeu) et un retour arrière a lieu si le
  service ne redémarre pas : `client-linux/cmd/maj`,
  `outils/manifeste`, `noeud/maj`.
- Preuve : `scripts/verifier-m11.sh`.

### 5. Compromission de GitHub, de la CI ou de la chaîne de publication

Un attaquant qui pousse du code ou réécrit un artefact pourrait publier un
binaire malveillant.

- Actions GitHub épinglées par empreinte SHA-40, permissions minimales par job,
  aucun `pull_request_target` : `.github/workflows/*.yml`, contrôlé par
  `scripts/ci/lint.sh`.
- Compilations reproductibles et comparaison d'octets :
  `scripts/ci/reproduire.sh`, `scripts/verifier-m21.sh`.
- Manifeste signé hors ligne, clé privée jamais dans le dépôt :
  `outils/publier`, `noeud/README.md`, `docs/reproduire.md`.
- Attestations de provenance des images et empreintes dans `images.txt` :
  `.github/workflows/release.yml`, `scripts/ci/images-release.sh`.

### 6. Compromission du registre ou du contrôleur

Un contrôleur compromis peut orienter des clients vers de faux nœuds.

- Le registre ne sert que des agrégats et des adresses tronquées :
  `controleur/registre/reseau.go`, `scripts/verifier-m22.sh`.
- La page publique ne contient ni contact, ni défi, ni nom demandé.
- Les listes d'adresses restent signées : un contrôleur compromis ne peut pas
  forger la signature (clé hors ligne).

### 7. Compromission du routeur (OpenWrt)

Le routeur voit tout le LAN ; c'est un point de confiance assumé.

- Le service n'écoute que sur `127.0.0.1:5353`, dnsmasq est le seul résolveur
  visible : `client-openwrt/files/etc/init.d/tordns`.
- La configuration refuse une interface LAN invalide et ne journalise aucun nom.
- Preuve : `scripts/verifier-m23.sh` (aucun nom dans `logread`).

## Hors périmètre

- Un attaquant qui contrôle simultanément l'appareil et le routeur.
- La censure de Tor lui-même (ponts, Snowflake) : non implémentée.
- La sécurité physique de la carte SD d'un nœud.
- Les vulnérabilités du noyau Linux, de Docker, de Tor ou d'OpenWrt.
