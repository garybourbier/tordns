# Dépendances du client Android

Aucun binaire n'est versionné : F-Droid refuse les `.jar` dans le code source,
et `scripts/telecharger-libs.sh` télécharge les deux dépendances Java depuis
Maven Central avec une empreinte SHA-256 épinglée dans le script. Le cache va
dans `build/libs/` (ignoré par git) et sert aux constructions suivantes.

## Java

| Dépendance | Version | Licence | Usage | Empreinte SHA-256 |
|---|---|---|---|---|
| [dnsjava](https://github.com/dnsjava/dnsjava) | 3.6.3 | BSD-2-Clause | validation DNSSEC (`ValidatingResolver`) | `ce279b5acb753f58661756b6dcacdcc4dee76748cff04d2abf14edcc7e26a8de` |
| [slf4j-api](https://www.slf4j.org/) | 2.0.16 | MIT | journalisation de dnsjava, sans fournisseur | `a12578dde1ba00bd9b816d388a0b879928d00bab3c83c240f7013bf4196c579a` |

Ni l'un ni l'autre ne dépend d'un service Google, ne contient de traceur ni de
publicité. Le reste du code Java n'utilise que l'API Android (`android.jar`).

## Rust (bibliothèque Tor, `rust/Cargo.toml`)

La logique Tor et DoH vit dans le crate partagé `outils/arti-rust`
(`tordns-tor`), également lié par le client iOS ; `rust/` ne garde que le pont
JNI et la vérification du manifeste.

| Dépendance | Version | Licence |
|---|---|---|
| tordns-tor (dépôt, `outils/arti-rust`) | — | MIT |
| tordns-manifeste (dépôt, `outils/manifeste-rust`) | — | MIT |
| [jni](https://github.com/jni-rs/jni-rs) | 0.21 | MIT OR Apache-2.0 |

Dépendances du crate partagé (`outils/arti-rust/Cargo.toml`) :

| Dépendance | Version | Licence |
|---|---|---|
| [arti-client](https://gitlab.torproject.org/tpo/core/arti) | 0.48 | MIT OR Apache-2.0 |
| [tor-rtcompat](https://gitlab.torproject.org/tpo/core/arti) | 0.48 | MIT OR Apache-2.0 |
| [tokio](https://tokio.rs/) | 1 | MIT |
| [rustls](https://github.com/rustls/rustls) | 0.23 | Apache-2.0 OR ISC OR MIT |
| [futures](https://github.com/rust-lang/futures-rs) | 0.3 | MIT OR Apache-2.0 |

Les dépendances transitives sont figées par `rust/Cargo.lock` (et
`outils/arti-rust/Cargo.lock`) et se listent avec `cargo tree --locked
--manifest-path client-android/rust/Cargo.toml` :
toutes sont sous MIT, Apache-2.0, BSD, ISC ou MPL-2.0, aucune sous licence
propriétaire. Aucune ne joint un service Google ni un traceur.

## Licences du projet

Le client Android est distribué sous MIT (voir `LICENSE` à la racine du dépôt) ;
dnsjava (BSD-2-Clause) et slf4j (MIT) gardent leurs licences d'origine,
compatibles avec la redistribution dans un APK.
