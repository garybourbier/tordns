# Calendrier de la racine DNSSEC et livraison d'une ancre

Document d'exploitation (mission 28, point 7). Il décrit le comportement réel
du code, pas une intention : les ancres sont **compilées** dans les clients, et
le manifeste signé ne transporte aujourd'hui aucune ancre.

## État de la racine

Source : IANA, <https://data.iana.org/root-anchors/root-anchors.xml> et
<https://www.iana.org/dnssec/status> (RFC 9718).

| Ancre | Key tag | État | Dates |
|---|---|---|---|
| KSK-2024 | 38696 | signe la racine | active depuis le 11/10/2026 |
| KSK-2017 | 20326 | publiée, encore acceptée | révoquée le 11/01/2027, retirée de la zone le 22/03/2027 |

Depuis le 11/10/2026, la racine n'est plus signée que par KSK-2024. Un client
qui ne connaîtrait que 20326 refuserait (SERVFAIL) toutes les zones signées.
Les clients embarquent donc **les deux**, et la chaîne est acceptée dès qu'une
ancre la valide.

Emplacements dans le dépôt :

- Linux et macOS : `client-linux/relais/dnssec.go`, constante `ancreRacineDS`
  (DS SHA-256 des deux clés, séparés par `;`) ;
- Windows : `client-windows/src/dnssec.rs`, ancre hickory d'origine plus
  `KSK_2024` (`src/ancres/38696.rsa`) ;
- Android : `client-android/app/src/main/java/org/tordns/client/Dnssec.java`,
  `ANCRE_KSK_2017` et `ANCRE_KSK_2024` ; le démarrage échoue si aucune ancre
  n'est chargée.

## Livraison d'une nouvelle ancre

Il n'existe pas de mise à jour d'ancre « à chaud » : le manifeste signé
(`outils/manifeste`) porte la version, l'expiration, les URL/taille/SHA-256 des
fichiers, les empreintes d'images et les adresses `.onion` — pas d'ancre DNSSEC.
Une nouvelle ancre arrive donc par une **nouvelle version du client** :

1. ajouter la nouvelle ancre (DS) à côté des existantes dans chaque client ;
2. laisser les anciennes jusqu'à leur retrait par l'IANA, pour ne pas casser
   les résolveurs qui n'ont pas encore la nouvelle ;
3. publier une release : le manifeste signé authentifie les binaires qui
   contiennent la nouvelle ancre (version croissante, expiration, SHA-256) ;
4. les clients installés se mettent à jour par `tordns-client-maj` (Linux),
   le mécanisme de mise à jour signée Windows/Android, puis redémarrent.

Conséquence : une rotation doit être livrée **avant** la date de retrait de
l'ancienne ancre. Pour KSK-2017, la version embarquant KSK-2024 devait être
installée avant le 22/03/2027 ; c'est déjà le cas des versions actuelles.

### Invariant des trois plateformes

Une ancre ajoutée à un seul client est pire qu'aucune ancre ajoutée : cette
plateforme change de racine de confiance sans que les autres suivent, et une
release peut partir avec un ensemble incohérent. L'ensemble livré doit rester
le même partout, et il doit contenir **au moins deux** ancres tant que l'IANA
n'a pas retiré l'ancienne :

- Linux : `TestDNSSECAncresLivrees` exige les deux DS et le bon nombre
d'ancres, `TestDNSSECPlusieursAncresUneSuffit` prouve qu'une chaîne est
  acceptée dès qu'une ancre la valide ;
- Windows : `les_ancres_du_roulement_coexistent` exige KSK-2024 **et** toutes
  les ancres par défaut de hickory, et au moins deux ancres au total ;
- Android : le test des ancres livrées exige les deux DS (key tags 20326 et
  38696) et `ancresLivrees()` renvoie exactement les mêmes.

Ces trois tests tournent dans `scripts/verifier-m28.sh` : une rotation qui
oublie une plateforme échoue avant la release.

### Prochaine rotation

À la publication de l'ancre suivante par l'IANA :

1. ajouter son DS dans les trois clients, dans le même commit, sans retirer
   KSK-2024 ;
2. faire passer les trois suites (l'invariant ci-dessus échoue si une
   plateforme manque) ;
3. livrer une release signée avant le retrait de KSK-2024 ;
4. ne retirer l'ancienne ancre qu'après sa disparition de la zone racine, dans
   une release ultérieure.

Si une livraison d'ancre par le manifeste est ajoutée un jour, elle devra être
un champ explicite et revu (une ancre est une racine de confiance : la faire
transporter par le même manifeste que les binaires ne change pas le modèle de
confiance, la clé Ed25519 de publication restant hors ligne).

## Vérifier une installation

`tordns-verifier-dnssec` (mission 28) valide un nom réel avec la même chaîne
que le relais :

```sh
cd client-linux
go run ./cmd/verifier-dnssec -doh https://cloudflare-dns.com/dns-query cloudflare.com
# verdict : accepté DNSSEC — cloudflare.com
```

Le nom est envoyé au résolveur DoH indiqué : c'est un outil d'audit, pas le
chemin du client (TorDNS résout via Tor). Le diagnostic ne journalise rien.

Résultats du 27/11/2026 sur cette machine :

- `cloudflare.com` → accepté DNSSEC ;
- `dnssec-failed.org` (cassé exprès) → REFUSÉ, « aucune DNSKEY … ne correspond
  au DS » ;
- `google.com` (zone non signée) → « zone non signée (délégation sans DS) ».

NON PROUVÉ : Windows et Android contre de vrais domaines signés (leurs tests
restent hors ligne), et le diagnostic à travers Tor (les essais ci-dessus
passent par HTTPS direct).
