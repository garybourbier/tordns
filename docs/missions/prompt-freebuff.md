# Prompt à coller dans Freebuff (une mission par session)

Remplacer NN par le numéro de la mission (ordre : 07, 13, 08, 09, 11, 10, 12).

```text
Tu travailles dans le dépôt TorDNS (~/Projets/tordns). Lis d'abord AGENTS.md, puis
docs/missions/00-lire-moi.md EN ENTIER, puis docs/missions/NN-*.md. Fais la mission NN et
rien d'autre.

Règles :
- Aucun secret ni adresse .onion réelle dans le dépôt ; les clés de test sont jetables et
  ignorées par git.
- Commit local sur master seulement (message en français, « Mission NN : … ») ; JAMAIS de
  git push, jamais de connexion à un serveur.
- Termine par scripts/verifier-mNN.sh, lance-le, et copie sa sortie dans le message du
  dernier commit. Ce qui n'a pas pu être prouvé, écris-le comme non prouvé.
- Bloqué après trois essais sur un point : écris-le dans docs/missions/journal.md
  (« à confier à Claude ») et continue le reste.
- À la fin, ajoute une entrée dans docs/missions/journal.md : fait, reste, demandé à qui.
```
