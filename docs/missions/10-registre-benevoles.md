# Mission 10 — Registre : les nœuds bénévoles s'ajoutent seuls

But : un bénévole lance `installer.sh --rejoindre`, et son nœud entre tout seul dans le pool
**communauté** après une quarantaine, puis en sort tout seul s'il se comporte mal.

## Règle de sécurité (non négociable)

Un nœud bénévole n'entre JAMAIS dans le pool cœur automatiquement. Le pool cœur reste la
liste écrite à la main par Gary (mission 9). L'admission automatique ne concerne que
l'adresse communauté.

## À livrer

- **Registre** (dans `controleur/`, exposé par un service caché à part) : petite API HTTP :
  - `POST /inscription` `{adresse_instance, contact_facultatif}` → renvoie un défi aléatoire ;
  - le registre va lire `http://<adresse_instance>/.well-known/tordns/defi` : si le nœud y
    sert le défi, il prouve qu'il contrôle cette adresse ; sinon refus ;
  - limite d'inscriptions par circuit et par jour, liste noire d'adresses évincées.
- **Sondes** (même hôte) qui interrogent chaque nœud candidat ou admis, à intervalles
  aléatoires, avec un jeu de domaines tirés au hasard dans une liste publique :
  - justesse : réponses comparées à la résolution du contrôleur (tolérance pour le DNS
    géographique : comparer les enregistrements signés DNSSEC, pas les IP de CDN) ;
  - DNSSEC : drapeau AD sur les zones signées, SERVFAIL sur une zone cassée ;
  - délai et disponibilité ;
  - aucune sonde n'écrit le nom des domaines testés dans un journal.
- **Admission** : candidat → admis après N heures de sondes toutes réussies (défaut 72 h,
  réglable) ; admis → évincé après X échecs de justesse (un seul mensonge DNSSEC suffit) ou
  indisponibilité prolongée. À chaque changement : régénérer la configuration du 2e
  Onionbalance (adresse communauté) et le recharger.
- **Page publique** du registre : liste des nœuds admis (adresse d'instance, ancienneté,
  disponibilité), sans rien sur leurs utilisateurs.
- `installer.sh --rejoindre <adresse du registre>` : sert le défi, s'inscrit, affiche l'état.

## Preuve (`scripts/verifier-m10.sh`)

Sur la machine de test : un nœud honnête passe candidat puis admis (quarantaine raccourcie
pour le test), un nœud **menteur** (Unbound qui réécrit une réponse signée) est évincé, un
nœud qui ne sert pas le défi est refusé.

## Ce qu'on ne peut pas prouver

Qu'un bénévole ne journalise pas. L'écrire dans la page publique et dans les clients.
