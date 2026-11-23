# Dépendances Java embarquées

Ces deux jars sont versionnés pour que la construction Android reste hors ligne
et reproductible sans Gradle :

| Fichier | Version | Licence | Source |
|---|---|---|---|
| `dnsjava-3.6.3.jar` | 3.6.3 | BSD 2-clause | https://github.com/dnsjava/dnsjava |
| `slf4j-api-2.0.16.jar` | 2.0.16 | MIT | https://www.slf4j.org/ |

Ils ne contiennent aucun secret. `dnsjava` fournit la validation DNSSEC
(`ValidatingResolver`) ; `slf4j-api` est sa dépendance de journalisation, sans
fournisseur (avertissement « NOP logger » attendu). Mettre à jour les deux
jars ensemble et revérifier `scripts/tester.sh` et `scripts/construire.sh`.
