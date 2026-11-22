# Journal du chantier 2

Une entrée par mission : fait, reste, demandé à qui.

## Mission 7 — Durcissement (22/11/2026)

- **Fait** : limite de débit par circuit Tor via PROXY v2 (Tor → Caddy →
  passerelle, table bornée en mémoire, purge, plafond global conservé) ;
  `SocksPort 0` et client Tor de test séparé (profil `test`, aucun port
  publié) ; PoW, `HiddenServiceMaxStreams 64` avec fermeture du circuit,
  `VanguardsLiteEnabled 1` ; preuve de bout en bout (`example.com` AD,
  `dnssec-failed.org` SERVFAIL, 429 sur un circuit puis 200 sur un autre,
  journaux sans nom de domaine) ; README serveur et racine remis d'accord
  avec le code.
- **Reste** : l'effet réel de la PoW derrière Onionbalance n'est pas mesuré
  (prévu mission 9) ; l'installation et le service Windows restent non
  prouvés hors Windows (missions 5-6) ; aucun test sur un VPS distant.
- **Demandé à qui** : rien de bloqué, aucune demande. La question PoW/Onionbalance
  revient à la mission 9 (Gary/Claude pour la relecture).

## Mission 13 — Clients : cache, fuites, paquets hostiles (22/11/2026)

- **Fait** : les trois caches (Linux, Windows, Android) expirent au plus petit
  TTL de la section réponse, et NXDOMAIN/NODATA suivent le TTL négatif du SOA
  (minimum du TTL et de MINIMUM, RFC 2308), avec plafond 1 h, TTL nul non caché
  et TTL servi décroissant. Diagnostic de fuites : Linux `--diagnostic`
  (resolv.conf IPv4/`::1`/stub systemd, politiques DoH) avec code 1 s'il reste
  une fuite ; Windows `--diagnostic` (netsh IPv4/IPv6, DoH système et
  navigateur, SMHNR) ; Android lit le DNS privé (DoT) et guide vers
  « Désactivé ». Chaque client absorbe 10 000 paquets aléatoires sans panique.
  `scripts/verifier-m13.sh` passe en entier (27 tests Windows, 33 vérifications
  Android, tests Go, compilation Android, diagnostic sur fixture qui fuit puis
  corrigée).
- **Reste** : le diagnostic Windows réel (netsh/registre) et le bandeau DoT sur
  un appareil Android n'ont pas été exécutés ici (aucun hôte Windows/Android) ;
  le DoH des profils de navigateur n'est pas lisible de façon fiable, seules
  les politiques d'entreprise et le réglage Android sont inspectés.
- **Demandé à qui** : rien de bloqué. Pour une preuve sur matériel réel,
  demander à Gary un passage Windows 11 et un appareil Android (DNS privé
  activé puis désactivé) ; sinon la relecture Claude suffit.
