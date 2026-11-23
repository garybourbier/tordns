# Mission 18 — README à jour

But : le README dit ce qu'est TorDNS **aujourd'hui**, sans promesse ni jargon inutile.

## À livrer

- `README.md` réécrit, dans cet ordre :
  1. une phrase de présentation + badges (CI, dernière release, licence) ;
  2. **Télécharger** : tableau plateforme × architecture → lien de release (mêmes noms que
     le site, même source), lien vers la page GitHub Pages ;
  3. **Démarrage rapide** par plateforme (5 lignes chacune max, renvoi vers le README du
     client) ;
  4. **Héberger un nœud** : installation en une commande, images GHCR, cœur / communauté,
     inscription comme bénévole ;
  5. **Architecture** : le schéma actuel (réseau Onionbalance, registre, mises à jour
     signées), mis à jour depuis `chantier-2-cadrage.md` ;
  6. **Sécurité** : modèle de menace en clair, ce qui est prouvé, ce qui ne l'est pas encore
     (repris de `docs/missions/journal.md`, pas inventé), vérification des téléchargements
     (`SHA256SUMS`, attestations, manifeste signé), lien `SECURITY.md` ;
  7. **Développer** : scripts de `scripts/ci/`, comment lancer les preuves, organisation des
     dossiers ;
  8. historique court des chantiers (1 ligne par mission, lien vers le journal) ; licence.
- Supprimer les formulations marketing (« ultra-sécurisé », « absolue », « incensurable »)
  au profit de faits vérifiables.
- Mettre à jour les README de `client-*/` et `noeud/` pour qu'ils renvoient au téléchargement
  de la release au lieu de la seule compilation locale.

## Preuve (`scripts/verifier-m18.sh`)

Chaque lien relatif du README existe dans le dépôt ; chaque lien de téléchargement
correspond à un nom produit par `release.yml` ; aucune adresse `.onion` réelle ; aucun
terme de la liste marketing ci-dessus.
