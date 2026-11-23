# Mission 25 — Publication sur F-Droid

But : TorDNS installable depuis F-Droid, la boutique libre que les publics visés utilisent.

## À livrer

- Vérifier ce qu'exige F-Droid pour construire l'app **depuis le code** sur leurs serveurs :
  la chaîne actuelle (sans Gradle, `construire.sh`, Rust Arti via NDK) passe-t-elle dans
  `fdroidserver` ? Si non, ajouter un build Gradle minimal **à côté** (sans casser
  `construire.sh`) que F-Droid sait lancer, avec la bibliothèque Rust compilée par une étape
  `prebuild`/`build` de la recette.
- Aucune dépendance non libre, aucun service Google, aucun traceur : lister chaque
  dépendance avec sa licence dans `client-android/DEPENDANCES.md` ; `dnsjava` et `slf4j`
  doivent venir de Maven Central (pas de `.jar` binaire dans le dépôt pour F-Droid :
  remplacer `client-android/libs/` par une récupération vérifiée).
- Métadonnées fastlane dans `client-android/fastlane/metadata/android/{fr-FR,en-US}/`
  (titre, description courte et longue, captures, journal des versions).
- Recette `metadata/org.tordns.client.yml` prête à proposer à `fdroiddata`, avec
  `AutoUpdateMode: Version` et `UpdateCheckMode: Tags`, et la piste **build reproductible**
  (F-Droid publie alors l'APK signé par Gary si le sien est identique au leur : s'appuyer
  sur la mission 21).
- `docs/fdroid.md` : la procédure de soumission (c'est Gary qui ouvre la demande sur
  GitLab, pas toi).

## Preuve (`scripts/verifier-m25.sh`)

`fdroid lint` et `fdroid build` réussissent en local dans le conteneur officiel
`registry.gitlab.com/fdroid/fdroidserver` sur la recette ; `fdroid scanner` ne trouve aucun
binaire non libre. NON PROUVÉ attendu : acceptation par F-Droid.
