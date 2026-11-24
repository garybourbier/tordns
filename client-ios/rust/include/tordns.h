/* ABI C du client TorDNS pour iOS.
 *
 * Le module Rust `tordns_ios` est compilé en bibliothèque statique
 * (`libtordns_ios.a`) puis lié par Xcode. Toute chaîne et tout tampon rendus
 * par ce module doivent être libérés par `tordns_liberer_chaine` ou
 * `tordns_liberer_reponse` : Swift ne doit jamais appeler `free()` dessus.
 *
 * Aucune fonction ne journalise de nom de domaine, et aucun panneau de ce
 * module n'écrit hors des répertoires d'état/cache passés à `tordns_demarrer`.
 */

#ifndef TORDNS_H
#define TORDNS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Réponse binaire. `code` : 0 succès, -1 Tor pas démarré, -2 erreur
 * (le message est dans `tordns_derniere_erreur`). */
typedef struct {
    uint8_t *donnees;
    size_t longueur;
    int32_t code;
} TordnsReponse;

/* Bootstrap Tor avec les répertoires d'état et de cache de l'application.
 * Rend NULL en cas de succès, sinon un message d'erreur à libérer. */
char *tordns_demarrer(const char *etat, const char *cache);

/* Ferme Tor et rend les circuits. */
void tordns_arreter(void);

/* 1 si Tor est bootstrappé, 0 sinon. */
int32_t tordns_demarre(void);

/* POST DoH vers `<onion>:80` par un circuit Tor. `delai_ms` est ramené entre
 * 1000 et 30 000 ms. */
TordnsReponse tordns_doh(const char *onion,
                         const uint8_t *requete,
                         size_t longueur,
                         uint32_t delai_ms);

/* GET borné vers `<onion>:80` (manifeste, paquet du miroir). */
TordnsReponse tordns_telecharger(const char *onion,
                                 const char *chemin,
                                 size_t maximum);

/* Vérifie le manifeste signé (clé publique épinglée dans le binaire) et rend
 * `version|url|taille|sha256|cle_suivante|coeur|secours|communaute`, ou un
 * message d'erreur. La chaîne rendue est à libérer. */
char *tordns_verifier_manifeste(const uint8_t *manifeste,
                                size_t longueur_manifeste,
                                const uint8_t *signature,
                                size_t longueur_signature,
                                int64_t version_installee,
                                int64_t maintenant);

/* Dernière erreur du module Tor, à libérer. */
char *tordns_derniere_erreur(void);

/* Libère une chaîne rendue par ce module (pointeur NULL accepté). */
void tordns_liberer_chaine(char *pointeur);

/* Libère le tampon d'une réponse (tampon NULL accepté). */
void tordns_liberer_reponse(TordnsReponse reponse);

#ifdef __cplusplus
}
#endif

#endif /* TORDNS_H */
