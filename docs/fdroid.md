# Publication sur F-Droid

La demande se fait sur [f-droid.org](https://f-droid.org) via une merge request
sur `fdroiddata` (GitLab). C'est **Gary** qui ouvre la demande et qui pousse le
tag : la recette est prête, rien n'est envoyé par l'agent.

## Ce qui est prêt dans le dépôt

| Élément | Emplacement |
|---|---|
| Recette fdroiddata | `metadata/org.tordns.client.yml` (copie à déposer dans `metadata/` de fdroiddata) |
| Métadonnées de la fiche | `client-android/fastlane/metadata/android/{fr-FR,en-US}/` |
| Dépendances et licences | `client-android/DEPENDANCES.md` |
| Téléchargement vérifié des jars | `client-android/scripts/telecharger-libs.sh` |
| Construction sans Gradle | `client-android/scripts/construire.sh` |

## Ce que F-Droid exige, et comment le dépôt y répond

1. **Construire depuis le code, sur leurs serveurs.** La recette ne dépend
   d'aucun binaire : `construire.sh` compile Arti avec cargo puis assemble
   l'APK avec `aapt2`, `javac`, `d8`, `zipalign`. F-Droid sait lancer des
   commandes arbitraires (`build:`), le cas s'applique ; aucun build Gradle
   n'est donc nécessaire.
2. **Aucun `.jar` versionné.** F-Droid les refuse (son scanner les signale
   comme binaires inconnus). `telecharger-libs.sh` récupère `dnsjava` et
   `slf4j-api` depuis Maven Central avec une empreinte SHA-256 épinglée dans le
   script ; `fdroid scanner` ne trouve plus de binaire non libre.
3. **Rust sur le serveur de compilation.** L'image F-Droid n'embarque pas
   cargo. La recette l'installe par `sudo:` (`rustup`, `gcc`, `libc-dev`) puis
   `prebuild:` épingle la version (`rustup default 1.96.1`) et les trois cibles
   Android — c'est le schéma employé par `webtor.app` dans fdroiddata.
4. **NDK.** `ndk: r26b` (NDK 26.3.11579264) pour les `.so` Android 16 (pages de
   16 Kio).
5. **Versions.** Nom et code viennent du tag (`v0.8.0` → `0.8.0` / `800`) ;
   `AutoUpdateMode: Version` et `UpdateCheckMode: Tags` suivent les tags.
6. **Licence libre, aucun traceur.** MIT pour l'application, BSD 2-clause pour
   dnsjava, MIT pour slf4j ; aucune dépendance Google, aucun service tiers.

## Procédure de soumission

1. Gary crée le tag `vX.Y.Z` et pousse (`git tag -s`, puis `git push --tags`).
   La recette doit alors porter le SHA du commit tagué dans `commit:`, pas un
   nom de tag.
2. Gary vérifie la construction chez lui :

   ```bash
   fdroid lint org.tordns.client
   fdroid build --test org.tordns.client
   ```

3. Gary se connecte à GitLab, fork `fdroiddata`, y copie
   `metadata/org.tordns.client.yml`, crée une branche
   `org.tordns.client` et ouvre une merge request en cochant « I am the
   upstream author ».
4. Un mainteneur F-Droid relit, demande éventuellement des changements, puis
   fusionne. La première publication arrive au cycle suivant (généralement
   quelques jours à deux semaines).
5. Pour publier l'APK signé par Gary plutôt que celui de F-Droid, ajouter
   `AllowedAPKSigningKeys` avec l'empreinte SHA-256 du certificat de signature
   de Gary, une fois qu'une construction reproductible a été comparée
   (mission 21 : `scripts/ci/reproduire.sh`).

## Ce qui reste à Gary

- Le tag, la clé de signature Android et l'envoi de la merge request.
- Les captures d'écran (`fastlane/.../images/phoneScreenshots/`) : elles
  demandent un appareil ou un émulateur, absents de la machine de l'agent.
- L'acceptation par F-Droid, qui ne peut pas se prouver en local.
