# Mission 19 — Restes de la relecture Claude du 23/11

Deux défauts relevés et non corrigés (voir la fin de `journal.md`).

## 1. La sonde du registre élimine des bénévoles honnêtes

`controleur/registre/registre.go` (`sonder`) exige des adresses A **identiques** à celles de
la référence. Des domaines servis par CDN ou en tourniquet répondent différemment selon le
résolveur et l'instant : une seule différence classe le candidat en « mensonge » et le
supprime définitivement.

- Comparer : RCODE égal, bit AD égal, et **au moins une adresse en commun** (ou, pour une
  réponse signée, la même validation DNSSEC) ; un ensemble disjoint sur un domaine signé
  reste un mensonge.
- Un écart non signé ne compte que comme « douteux » : il faut N écarts (configurable) sur
  des domaines différents pour disqualifier.
- Tests : réponses en tourniquet (intersection non vide) acceptées ; adresse inventée sur
  un domaine signé → mensonge ; `dnssec-failed.org` résolu (AD absent attendu SERVFAIL) →
  mensonge.

## 2. Une mise à jour Linux refusée par le service est retentée sans fin

`client-linux/cmd/maj` : si le nouveau binaire ne redémarre pas, on revient en arrière mais
l'état ne retient rien ; au passage suivant du minuteur, la même version est réinstallée et
coupe à nouveau le service. Même examen pour `noeud/maj` et le client Windows.

- Noter la version rejetée dans l'état (`rejetee: N`) et ne plus la retenter ; une version
  supérieure à N est essayée normalement.
- Tests : v2 cassée → retour v1, second passage → « v2 déjà rejetée », pas de redémarrage ;
  v3 saine → installée.

## Preuve (`scripts/verifier-m19.sh`)

Les tests ci-dessus, plus M10, M11 et M12 rejouées vertes.
