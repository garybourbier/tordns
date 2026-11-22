# Mission 13 — Clients : cache qui respecte le TTL, fuites DNS, tests

Relecture de Claude du 22/11, partie clients.

## 1. Cache

Vérifier dans les trois clients (`client-linux/cache.go`, `client-windows/src/cache.rs`,
`client-android/.../DnsCache.java`) que chaque entrée expire au TTL de la réponse (le plus
petit TTL de la section réponse ; TTL négatif d'après le SOA pour NXDOMAIN), avec un plafond
(1 h) et un plancher. Ne pas servir de réponse périmée. Test unitaire par client.

## 2. Fuites DNS

- **Linux** : l'IPv6 (`::1` et résolveurs IPv6 de la box), `systemd-resolved` qui contourne le
  relais, le DoH intégré des navigateurs. Livrer une commande `tordns-client --diagnostic` qui
  dit ce qui fuit et comment le fermer.
- **Windows** : requêtes IPv6, DoH de Windows 11 et des navigateurs, « Smart Multi-Homed Name
  Resolution ». Même diagnostic dans l'interface ou en ligne de commande.
- **Android** : DNS privé du système (DoT) qui passe à côté du VpnService ; le détecter et
  guider l'utilisateur.

## 3. Tests

Android : tests unitaires de `DnsMessage` et `Paquet` (analyse de paquets malformés, tronqués,
compression de noms en boucle). Les trois clients : un paquet DNS hostile ne fait jamais
planter le relais (test par fuzz court, 10 000 entrées aléatoires).

## Preuve (`scripts/verifier-m13.sh`)

Tests verts des trois clients, sortie du diagnostic sur une machine qui fuit puis corrigée.
