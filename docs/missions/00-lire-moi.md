# Chantier 2 — TorDNS redondant, ouvert aux bénévoles, à jour tout seul

Cadrage du 22/11/2026. Les missions 1 à 6 ont livré un nœud complet (serveur + clients Linux,
Android, Windows). Ce chantier en fait un **réseau** : plusieurs nœuds sur plusieurs sites
derrière une seule adresse `.onion`, des nœuds de bénévoles qui s'ajoutent seuls, et des
programmes (nœuds comme clients) qui se mettent à jour seuls, de façon sûre.

Lire ce fichier en entier avant toute mission, puis la mission demandée, et rien d'autre.

## Règles (toutes les missions)

1. **Aucun secret dans le dépôt** : clés `.onion`, clé maîtresse Onionbalance, clé de
   signature des mises à jour, mots de passe, adresses `.onion` de production. Les clés se
   génèrent en local dans des dossiers ignorés par git ; les exemples utilisent des clés
   jetables créées par les tests.
2. **Pas de push, pas de déploiement** : tu commites sur `master` localement, Gary relit
   (Claude) puis pousse. Aucune connexion aux VPS de Gary.
3. **Zéro journal** des requêtes DNS, partout, y compris dans les sondes et le registre.
4. **Preuve exigée** : chaque mission finit par un script `scripts/verifier-mNN.sh` qui
   démontre ce qui est livré (sortie copiée dans le message de commit). Ce qui n'a pas pu
   être prouvé est écrit comme tel, jamais présenté comme fait.
5. **Une mission = un sujet** : ne pas déborder sur la mission suivante. Ce qui coince plus
   de trois tentatives s'arrête et s'écrit dans `docs/missions/journal.md` (« à confier à
   Claude »).
6. Français pour les commentaires, les messages de commit et la doc, au niveau du code voisin.

## Architecture cible

```
                 clients (Linux, Android, Windows)
                         │  une seule adresse publique
                         ▼
           ┌──── adresse MAÎTRESSE (Onionbalance) ────┐
           │  descripteur qui agrège les points        │
           │  d'introduction des nœuds admis           │
           └───────┬──────────────┬──────────────┬─────┘
                   ▼              ▼              ▼
              nœud A (VPS 1)  nœud B (VPS 2)  nœud C (VPS 3)   ← pool « cœur » (Gary)
              Tor + Caddy + passerelle + Unbound (stack des missions 1-3)

           ┌──── adresse COMMUNAUTÉ (2e Onionbalance) ─┐
           └───────┬──────────────┬────────────────────┘
                   ▼              ▼
              nœud bénévole 1  nœud bénévole 2 …          ← admis automatiquement

  contrôleur (un hôte de Gary, hors des nœuds) :
    - Onionbalance (clés maîtresses)        - registre des nœuds (API .onion)
    - sondes : justesse DNS, DNSSEC, délai  - admission / éviction automatiques
```

### Pourquoi deux adresses

Un bénévole peut journaliser ou mentir : on ne peut pas prouver de l'extérieur qu'un nœud ne
journalise pas. L'adresse **cœur** ne contient que les nœuds de Gary (ajout manuel). L'adresse
**communauté** reçoit les bénévoles admis automatiquement après une quarantaine de sondes. Le
client choisit (cœur par défaut, communauté en secours ou par choix) et le dit clairement à
l'utilisateur. La validation DNSSEC côté client (mission 12) limite le mensonge sur les zones
signées, quel que soit le nœud.

### Onionbalance (v3)

- Chaque nœud garde sa propre adresse `.onion` d'instance et déclare
  `HiddenServiceOnionbalanceInstance 1` + un fichier `ob_config` contenant
  `MasterOnionAddress <adresse maîtresse>` (Tor ≥ 0.4.3).
- Le contrôleur fait tourner `onionbalance` avec la clé maîtresse et la liste des
  instances ; il publie le descripteur maître avec les points d'introduction des instances.
- Limite : un descripteur v3 porte au plus 20 points d'introduction → au-delà de ~6 nœuds
  actifs par adresse, Onionbalance en choisit une partie. À mesurer, pas à supposer.
- **À vérifier en mission 9** : la défense par preuve de travail (PoW) de Tor se règle par
  descripteur ; on ne sait pas si elle survit derrière Onionbalance. Le dire tel quel.

### Mises à jour signées

- Une clé Ed25519 de publication, **hors ligne chez Gary** ; sa clé publique est épinglée dans
  chaque programme.
- Un **manifeste** JSON signé : version (entier croissant), date d'expiration, pour chaque
  cible (`noeud`, `client-linux-amd64`, `client-windows`, `client-android`) l'URL, la taille,
  le SHA-256 ; pour les nœuds, les empreintes (`sha256:`) des images Docker. Il porte aussi la
  liste signée des adresses publiques (cœur, communauté) : les clients la suivent sans mise à
  jour de code.
- Refus si : signature fausse, version inférieure ou égale à l'installée (anti-retour
  arrière), manifeste expiré, empreinte différente. Échec = on garde la version en place.
- Tout se télécharge **par Tor** (miroir servi par chaque nœud sous `/maj/`, plus GitHub
  Releases en secours).

## Missions

| N° | Sujet | Dépend de |
|---|---|---|
| 7 | Durcissement relevé à la relecture (limite par circuit, PoW, SOCKS fermé, README vrai) | — |
| 8 | Nœud installable en une commande sur un VPS Debian, identité et page d'état | 7 |
| 9 | Contrôleur Onionbalance : adresse maîtresse sur 3 nœuds | 8 |
| 10 | Registre et admission automatique des nœuds bénévoles (pool communauté) | 9 |
| 11 | Mises à jour signées : outil de publication, nœuds, client Linux | 8 |
| 12 | Mises à jour Windows et Android, liste d'adresses signée, DNSSEC côté client | 11 |
| 13 | Clients : cache qui respecte le TTL, fuites DNS, tests de paquets hostiles | — |

Ordre conseillé : 7 → 13 → 8 → 9 → 11 → 10 → 12. Les missions 7 et 13 reprennent la
relecture de Claude du 22/11 sur les missions 1 à 6.
