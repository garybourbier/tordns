# TorDNS — Résolveur DNS Public & Privé via Services Cachés Tor

TorDNS est une initiative visant à fournir une infrastructure de résolution DNS publique, souveraine, chiffrée de bout en bout et sans le moindre journal d'activité (zero-log). En réponse aux restrictions géographiques, à la censure étatique et aux fermetures de résolveurs indépendants ouverts, TorDNS rend la résolution de noms accessible de manière anonyme et incensurable en s'appuyant sur le réseau Tor et le protocole DNS-over-HTTPS (DoH, RFC 8484).

---

## 1. Vision et Objectifs

1. **Incensurabilité & Anonymat** : Joignable exclusivement via un service caché Tor v3 (`.onion`). Le résolveur ne peut ni être bloqué par filtrage IP/SNI/BGP sur le réseau public, ni identifier l'IP des utilisateurs.
2. **Confidentialité absolue (Zero-Log)** : Aucun journal des requêtes, aucune corrélation temporelle conservée en mémoire ou sur disque.
3. **Validation & Intégrité (DNSSEC)** : Résolution récursive stricte interrogeant directement les serveurs racines de l'ICANN et les autorités TLD avec validation DNSSEC systématique (aucun intermédiaire menteur ni forwarder tiers non contrôlé).
4. **Accessibilité universelle** : Développement d'applications clientes légères avec pile Tor embarquée (Linux, Android, Windows) permettant à n'importe quel appareil de router ses résolutions DNS de façon transparente.

---

## 2. Architecture Technique

### Côté Serveur (Stack d'Hébergement)
Le serveur est conçu pour tourner dans un environnement conteneurisé minimaliste et isolé :

```
[ Client Tor / DoH ]
         │ (Trafic chiffré de bout en bout via circuits Tor)
         ▼
[ Service Caché Tor v3 ]
         │ (Trafic local HTTP clair sur loopback 127.0.0.1)
         ▼
[ Reverse Proxy Caddy / Nginx ]
         │ Endpoint standard: /dns-query (RFC 8484)
         ▼
[ Passerelle DoH (doh-server) ]
         │ Décode DoH (wireformat DNS) -> UDP/TCP 53
         ▼
[ Unbound (Validateur Récursif) ]
         │ Résolution récursive vers les racines DNS mondiales
         │ Cache local en RAM (TTL respecté)
         │ DNSSEC activé, récursivité fermée à l'extérieur
         ▼
[ Serveurs Racines & Autorités TLD ]
```

- **Unbound** : Moteur récursif racine ultra-sécurisé, configuré en mode silencieux (`verbosity: 0`, pas de logs de requêtes), refuse le type `ANY`, limite les tailles de buffers EDNS pour contrer l'amplification.
- **Passerelle DoH** : Convertit les requêtes HTTP POST/GET RFC 8484 en paquets DNS wireformat.
- **Caddy / Nginx** : Terminaison HTTP, rate limiting strict par circuit, filtrage des en-têtes et sécurisation du chemin `/dns-query`.
- **Démon Tor v3** : Expose le service caché avec clés générées hors dépôt et isolées.

### Côté Clients (Applications avec Tor Embarqué)
Puisque les systèmes d'exploitation envoient historiquement le DNS en UDP sur le port 53 et que Tor ne transporte nativement que des flux TCP/SOCKS, le client embarque sa propre chaîne :

```
[ Application / Navigateur / OS ]
         │ Requêtes UDP standard : 127.0.0.1:53
         ▼
[ Relais DNS Local TorDNS ]
         │ 1. Interception UDP/TCP port 53
         │ 2. Cache LRU haute performance en mémoire (réponses immédiates < 2ms)
         │ 3. Encodage DoH (RFC 8484)
         ▼
[ Démon Tor / Arti Embarqué ]
         │ Établit les circuits Tor locaux et joint le service .onion
         ▼
[ Service Caché TorDNS ]
```

---

## 3. Feuille de Route & Phases de Développement

### Phase 1 : Stack Serveur Conteneurisée
- Structure `serveur/` avec `docker-compose.yml`.
- Configuration Unbound récursif durci avec DNSSEC.
- Passerelle DoH légère et performante.
- Reverse proxy (Caddy) configuré pour `/dns-query`.
- **Validation** : Requêtes locales Unbound directes et requêtes DoH validées.

### Phase 2 : Exposition en Service Caché Tor v3
- Intégration du démon Tor en mode hidden service v3.
- Cloisonnement réseau : Unbound et DoH accessibles uniquement par le réseau interne du conteneur Tor.
- Scripts de gestion des clés et d'initialisation sécurisée.
- **Validation** : Résolution de noms validée via `curl --socks5-hostname 127.0.0.1:9050 http://<service-onion>/dns-query`.

### Phase 3 : Durcissement et Résilience
- Anti-amplification DNS et blocage des requêtes abusives (`ANY`).
- Rate limiting par connexion et protection contre le déni de service (DDoS).
- Isolation mémoire, profils seccomp / apparmor pour les conteneurs.
- Sonde de santé applicative anonyme (vérification du statut Unbound/Tor sans journalisation des requêtes).

### Phase 4 : Client Linux (Relais DNS Local)
- Implémentation d'un démon local (en Rust ou Go) dans `client-linux/`.
- Écoute sur `127.0.0.1:53` (UDP/TCP).
- Cache LRU mémoire haute vitesse.
- Client SOCKS5 intégré pour joindre l'adresse `.onion` configurée.
- **Validation** : Résolution transparente via `dig @127.0.0.1 <domaine>` avec un temps de réponse en cache < 5 ms.

### Phase 5 : Client Mobile Android
- Application Android dans `client-android/`.
- Utilisation de `VpnService` pour capturer localement et sans root l'ensemble du trafic DNS de l'appareil.
- Intégration de la bibliothèque **Arti** (implémentation Tor officielle en Rust) compilée pour Android (JNI/NDK).
- Sélecteur de modes (Always-on DNS, protection contre les fuites DNS).

### Phase 6 : Client Windows & Multiplateforme
- Service d'arrière-plan Windows avec gestionnaire de loopback TAP/WinTun.
- Packaging et installateurs signés.

---

## 4. Règles de Sécurité et Bonnes Pratiques

- **Zéro fuite de données d'identification** : Aucune clé privée `.onion` ni aucun secret ne doit figurer dans les commits ou le dépôt public.
- **Reproductibilité** : Chaque brique doit pouvoir être reconstruite à partir du code source et des fichiers de configuration versionnés.
- **Tests locaux isolés** : Tous les tests et développements s'effectuent en sandbox local avant tout déploiement en production.
- **Documentation claire** : Code, commits et guides documentés de façon rigoureuse et transparente.

---

## 5. Licence

Ce projet est distribué sous licence Open Source [MIT](LICENSE).
