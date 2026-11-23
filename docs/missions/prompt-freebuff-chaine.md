# Prompt Freebuff : toutes les missions du chantier 3 à la suite

À coller tel quel ; Freebuff reprend où il s'est arrêté grâce à docs/missions/journal.md.

```text
Tu travailles dans le dépôt TorDNS (~/Projets/tordns). Lis d'abord AGENTS.md, puis
docs/missions/00-lire-moi.md EN ENTIER (cadrage du chantier 3).

Fais les missions du chantier 3 l'une après l'autre, dans cet ordre :
19, 14, 15, 16, 17, 18, 20, 21, 22, 23, 24, 25, 26, 27.

Pour savoir où reprendre : lis la fin de docs/missions/journal.md et `git log --oneline` ;
une mission est faite si son commit « Mission NN : … » existe ET que son entrée est au
journal. Commence par la première mission de la liste qui n'est pas faite.

Pour CHAQUE mission, avant de passer à la suivante :
1. Lis docs/missions/NN-*.md et ne fais que cette mission (rien de la suivante).
2. Écris scripts/verifier-mNN.sh, lance-le, et copie sa sortie dans le message du dernier
   commit de la mission. Ce qui n'a pas pu être prouvé est écrit « NON PROUVÉ », jamais
   présenté comme fait.
3. Commit local sur master (message en français, « Mission NN : … »).
4. Ajoute une entrée dans docs/missions/journal.md : fait, reste / non prouvé, demandé à
   qui ; commite-la.
5. Relance les scripts verifier-mNN.sh des missions déjà faites du chantier 3 qui touchent
   les mêmes fichiers ; si l'un devient rouge, répare avant de continuer.

Règles permanentes :
- Aucun secret (clé, mot de passe, jeton, certificat) ni adresse .onion réelle dans le
  dépôt ou un workflow ; les clés de test sont jetables et ignorées par git.
- JAMAIS de git push, de tag, de release publiée, de connexion à un serveur de Gary, ni de
  demande envoyée à un tiers (F-Droid, OTF, Apple…) : tu prépares, Gary publie.
- Actions GitHub épinglées par empreinte de commit, permissions minimales par job.
- Bloqué après trois essais sur un point : écris-le au journal (« à confier à Claude »),
  et continue le reste de la mission puis les suivantes.
- Si une mission dépend d'une autre restée bloquée, fais tout ce qui n'en dépend pas et
  note le reste au journal.
- Arrête-toi seulement quand la mission 27 est faite ; termine par un résumé : missions
  faites, ce qui est NON PROUVÉ, ce qui est « à confier à Claude ».
```
