import Foundation

/// Erreur remontée par le module Tor (crate partagé `outils/arti-rust`).
struct ErreurTor: LocalizedError {
    let message: String
    var errorDescription: String? { message }
}

/// Seul point d'entrée Swift vers la bibliothèque Rust (`libtordns_ios.a`).
///
/// L'application et l'extension réseau compilent ce fichier : chacune a son
/// propre processus, donc son propre client Tor. Toute chaîne rendue par Rust
/// est libérée ici, jamais par Swift.
enum PontTor {
    /// Délai maximal d'une requête DoH (l'extension est tuée au-delà).
    static let delaiMaximum: TimeInterval = 10

    static func demarrer(etat: URL, cache: URL) throws {
        let message = etat.path.withCString { cheminEtat in
            cache.path.withCString { cheminCache in
                tordns_demarrer(cheminEtat, cheminCache)
            }
        }
        if let message {
            defer { tordns_liberer_chaine(message) }
            throw ErreurTor(message: String(cString: message))
        }
    }

    static func arreter() {
        tordns_arreter()
    }

    static var demarre: Bool {
        tordns_demarre() == 1
    }

    /// POST DoH vers `<onion>:80`. La requête est un message DNS brut.
    static func doh(onion: String, requete: Data, delai: TimeInterval = delaiMaximum) throws -> Data {
        let millisecondes = UInt32(max(1, min(delai, delaiMaximum)) * 1000)
        let reponse = onion.withCString { adresse in
            requete.withUnsafeBytes { octets in
                tordns_doh(
                    adresse,
                    octets.bindMemory(to: UInt8.self).baseAddress,
                    octets.count,
                    millisecondes
                )
            }
        }
        defer { tordns_liberer_reponse(reponse) }
        guard reponse.code == 0, let donnees = reponse.donnees else {
            throw ErreurTor(message: derniereErreur(ou: "Tor indisponible"))
        }
        return Data(bytes: donnees, count: reponse.longueur)
    }

    /// GET borné vers `<onion>:80` (manifeste, paquet du miroir).
    static func telecharger(onion: String, chemin: String, maximum: Int) throws -> Data {
        let reponse = onion.withCString { adresse in
            chemin.withCString { route in
                tordns_telecharger(adresse, route, maximum)
            }
        }
        defer { tordns_liberer_reponse(reponse) }
        guard reponse.code == 0, let donnees = reponse.donnees else {
            throw ErreurTor(message: derniereErreur(ou: "téléchargement impossible"))
        }
        return Data(bytes: donnees, count: reponse.longueur)
    }

    /// Vérifie le manifeste signé avec la clé publique épinglée dans le
    /// binaire, puis rend les champs utiles sous forme de dictionnaire.
    static func verifierManifeste(
        manifeste: Data,
        signature: Data,
        versionInstallee: Int64,
        maintenant: Date = Date()
    ) throws -> [String: String] {
        let record = manifeste.withUnsafeBytes { brut in
            signature.withUnsafeBytes { sig in
                tordns_verifier_manifeste(
                    brut.bindMemory(to: UInt8.self).baseAddress,
                    brut.count,
                    sig.bindMemory(to: UInt8.self).baseAddress,
                    sig.count,
                    versionInstallee,
                    Int64(maintenant.timeIntervalSince1970)
                )
            }
        }
        guard let record else {
            throw ErreurTor(message: "manifeste refusé")
        }
        defer { tordns_liberer_chaine(record) }
        let champs = String(cString: record).split(separator: "|", omittingEmptySubsequences: false)
        // Un refus est rendu comme un message libre, pas comme huit champs.
        guard champs.count == 8 else {
            throw ErreurTor(message: String(cString: record))
        }
        let noms = ["version", "url", "taille", "sha256", "cle_suivante", "coeur", "secours", "communaute"]
        return Dictionary(uniqueKeysWithValues: zip(noms, champs.map(String.init)))
    }

    static func derniereErreur(ou defaut: String) -> String {
        guard let pointeur = tordns_derniere_erreur() else { return defaut }
        defer { tordns_liberer_chaine(pointeur) }
        let message = String(cString: pointeur)
        return message.isEmpty ? defaut : message
    }

    /// Répertoires d'état et de cache du processus courant.
    static func repertoires() throws -> (etat: URL, cache: URL) {
        let racine = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("tordns", isDirectory: true)
        let etat = racine.appendingPathComponent("etat", isDirectory: true)
        let cache = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("tordns", isDirectory: true)
        for dossier in [etat, cache] {
            try FileManager.default.createDirectory(at: dossier, withIntermediateDirectories: true)
        }
        return (etat, cache)
    }
}
