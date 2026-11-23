# Mission 17 — Site de présentation sur GitHub Pages

But : une page publique qui explique TorDNS en une minute et donne les téléchargements de
chaque plateforme et du nœud Docker.

## À livrer

- `site/` : HTML + CSS statiques, **sans JavaScript tiers, sans police ni script distant,
  sans traceur, sans cookie** (le projet est un outil de vie privée : la page doit l'être
  aussi). Un petit script local est permis pour détecter la plateforme du visiteur et mettre
  son téléchargement en avant ; la page reste complète sans JavaScript.
- Contenu, en français (anglais en seconde page `en/` avec le même contenu) :
  1. ce que fait TorDNS et pour qui (censure, DNS menteurs, vie privée), en clair ;
  2. comment ça marche : un schéma SVG en ligne (client → Tor → adresse cœur/communauté →
     nœuds → Unbound DNSSEC) ;
  3. **Téléchargements** : une carte par plateforme (Windows x64/ARM, macOS universel,
     Linux amd64/arm64/armv7 + .deb, Android par ABI + universel) avec liens vers
     `https://github.com/garybourbier/tordns/releases/latest/download/<nom>` ; lien vers
     `SHA256SUMS` et la commande `gh attestation verify` ;
  4. **Héberger un nœud** : la commande d'installation en une ligne, les images GHCR,
     le lien vers `noeud/README.md`, la différence cœur / communauté ;
  5. sécurité et limites, dites honnêtement (ce qui est prouvé, ce qui ne l'est pas, un
     bénévole peut journaliser, DNSSEC côté client) ; lien vers `SECURITY.md` ;
  6. code source, licence MIT, comment contribuer.
- Les noms de fichiers des liens viennent d'**une seule source** (`site/telechargements.json`
  ou équivalent) partagée avec `release.yml` ; un test vérifie que chaque lien du site
  correspond à un fichier que la release produit.
- `.github/workflows/pages.yml` : déploie `site/` par `actions/upload-pages-artifact` +
  `actions/deploy-pages` sur push de `master` touchant `site/` ; `permissions: pages: write,
  id-token: write` sur ce job seulement.
- Accessibilité : contraste AA, lisible sur téléphone (pas de défilement horizontal à
  360 px), thème sombre par `prefers-color-scheme`, textes alternatifs.
- `SECURITY.md` à la racine : comment signaler une faille (par e-mail chiffré ou
  formulaire GitHub « Report a vulnerability », **sans adresse personnelle de Gary** :
  utiliser le signalement privé de GitHub).

## Preuve (`scripts/verifier-m17.sh`)

Validation HTML (`tidy` ou `vnu` si présent), aucune URL externe hors github.com dans
`site/` (grep), test de cohérence liens ↔ noms de release, capture des pages à 360 px et
1280 px (Chromium sans tête si présent). NON PROUVÉ attendu : la page en ligne (Gary active
Pages « GitHub Actions » dans les réglages du dépôt au premier push).
