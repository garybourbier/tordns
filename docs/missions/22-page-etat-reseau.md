# Mission 22 — Page publique de l'état du réseau

But : montrer, sans rien révéler des utilisateurs, si le réseau marche : nœuds en ligne,
délai de résolution, DNSSEC correct.

## À livrer

- Le contrôleur publie, à partir des sondes qu'il fait **déjà** (registre, Onionbalance),
  un fichier `etat-reseau.json` agrégé : par adresse (cœur, communauté) le nombre de nœuds
  admis et joignables, le délai médian et p95 des sondes sur 24 h, le taux de réponses
  DNSSEC correctes, l'heure de la dernière publication de descripteur. **Aucune donnée
  d'utilisateur**, aucune requête réelle, aucun compteur de trafic par nœud.
- Historique de 30 jours en agrégats horaires, taille bornée.
- Servi par le registre sous `/reseau` (HTML sans JavaScript, graphiques en SVG générés côté
  serveur) et `/reseau.json`, par son service caché.
- Une copie publique sur GitHub Pages : **seulement si Gary l'active** (variable de dépôt,
  désactivée par défaut) ; elle serait envoyée par un job qui lit `/reseau.json` par Tor —
  sinon la page du site renvoie vers l'adresse `.onion` du registre (lien rempli par
  configuration, jamais en dur).
- Les nœuds bénévoles apparaissent sous leur adresse d'instance tronquée (8 premiers
  caractères), jamais avec un contact.

## Preuve (`scripts/verifier-m22.sh`)

Tests de l'agrégation sur des sondes simulées (médiane, p95, fenêtres, purge à 30 jours) ;
la page et le JSON ne contiennent ni contact, ni adresse complète de bénévole, ni rien qui
ressemble à un nom de domaine demandé par un utilisateur ; HTML valide.
