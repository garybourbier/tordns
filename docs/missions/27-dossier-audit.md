# Mission 27 — Dossier pour un audit de sécurité externe

But : préparer tout ce qu'il faut pour qu'un auditeur indépendant (par exemple via le
programme Red Team Lab de l'Open Technology Fund) puisse auditer TorDNS vite et bien.
**Tu ne contactes personne et tu n'envoies rien** : c'est Gary qui dépose la demande.

## À livrer

- `docs/securite/modele-de-menace.md` : actifs (vie privée des requêtes, intégrité des
  réponses, clés `.onion` et de publication), adversaires (FAI/État censeur, nœud bénévole
  malveillant, attaquant réseau sur Tor, attaquant local sur le poste client, compromission
  de GitHub/CI), et pour chacun les défenses en place **avec le fichier qui les implémente**
  et la preuve qui les teste.
- `docs/securite/perimetre-audit.md` : composants dans le périmètre, versions/commit à
  auditer, comment monter un environnement de test (scripts des preuves), ce qui est hors
  périmètre, questions précises pour l'auditeur (ex. sécurité du registre bénévoles,
  validation DNSSEC maison du client Linux, chaîne de mise à jour, Onionbalance + PoW).
- `docs/securite/problemes-connus.md` : tout ce que le journal des missions marque NON
  PROUVÉ ou « reste », regroupé et classé par gravité, sans rien inventer.
- `docs/securite/demande-otf.md` : brouillon de demande (description du projet, public,
  impact, besoin d'audit) en anglais, à relire et envoyer par Gary.
- `SECURITY.md` complété (délai de réponse, versions supportées, signalement privé GitHub).

## Preuve (`scripts/verifier-m27.sh`)

Chaque chemin de fichier cité dans les documents existe ; chaque élément de
`problemes-connus.md` renvoie à une entrée du journal ; aucun secret, aucune adresse `.onion`
réelle, aucune donnée personnelle de Gary.
