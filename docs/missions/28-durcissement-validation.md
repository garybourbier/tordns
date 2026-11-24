# Mission 28 — Durcir la validation DNSSEC et le registre (suite d'une relecture externe)

Une relecture externe (24/11/2026) a été corrigée en partie par Claude dans le commit qui
ajoute cette mission : deux ancres racine (KSK-2017 et KSK-2024) côté Linux et Windows,
suppression d'une conclusion « zone non signée » faite sans preuve côté Linux, réponse
rendue depuis le message validé côté Windows avec contrôle du signataire et de la période de
validité, confirmation à un coup et adresses canoniques dans le registre. Le reste est ici.

**Règle d'écriture** : le dépôt est public. Le code, les tests et le journal décrivent le
COMPORTEMENT CORRECT attendu, jamais une marche à suivre pour exploiter l'ancien.

## À faire, dans cet ordre

1. **Android (`client-android/.../Dnssec.java`)** : charger les ancres racine de l'IANA
   (20326 et 38696) ; poser le bit DO et l'EDNS sur chaque requête sortante ; trancher sur le
   résultat de validation (RCODE et verdict) au lieu de relayer ; **échouer au démarrage si
   aucune ancre n'est chargée**. Tests dans `client-android/tests/` qui exigent un REFUS pour
   une réponse non signée d'une zone signée, et un transport factice qui ne signe QUE si le
   bit DO est posé.
2. **Windows (`client-windows/src/dnssec.rs`)** : zones non signées. hickory-proto 0.24 n'a pas
   de verdict « délégation non signée » : aujourd'hui une zone non signée finit en SERVFAIL,
   ce qui pousse les gens à `dnssec = non`. Prouver l'absence de DS par NSEC/NSEC3 (comme le
   fait le client Linux, `client-linux/relais/dnssec.go`) avant d'accepter une réponse non
   signée — ou monter de version de hickory APRÈS avoir lu son validateur et écrit ce qu'il
   vérifie réellement. Jamais d'acceptation sans preuve.
3. **Registre (`controleur/registre/`)** :
   - un échec imputable au contrôleur (référence injoignable) n'altère AUCUN compteur du
     bénévole : la passe est abandonnée ;
   - les indisponibilités « consécutives » se remettent à zéro après un succès ;
   - le quota journalier se décompte à la confirmation, pas à la revendication ;
   - la sonde utilise un identifiant DNS aléatoire (le parseur doit l'accepter) et des noms
     que le nœud ne peut pas lister à l'avance ;
   - rétention : la clé de limitation et le contact ne restent pas sur disque sans fin ;
     purge des candidats et des évincés anciens, avec motif d'éviction.
4. **Un jeu de vecteurs commun** aux trois validateurs (Linux, Windows, Android) : mêmes
   messages en entrée, même verdict attendu, cas de refus compris.
5. **Les bancs** : plus de `Quarantaine: time.Nanosecond` dans les tests qui parlent de la
   quarantaine ; fixtures DNSSEC accompagnées d'au moins un diagnostic (`--diagnostic`) qui
   valide un nom réel contre la vraie racine.
6. **Les textes**, seulement après le code : README et docs ne promettent que ce que le code
   tient (« la réponse du nœud n'est jamais relayée », « aucune corrélation temporelle en
   mémoire », « zone non signée acceptée »).
7. **Exploitation** : noter dans `docs/` le calendrier racine (KSK-2017 révoquée le
   11/01/2027, retirée le 22/03/2027) et la façon de livrer une nouvelle ancre par le
   manifeste signé.

## Preuve

`go test ./...` dans chaque module Go, `cargo test` dans `client-windows`, les tests Android ;
chaque correctif accompagné d'un test qui ÉCHOUE sans lui (le dire dans le journal, avec la
commande qui l'a montré).
