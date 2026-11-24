import Foundation

/// Réglages partagés entre l'application et l'extension réseau (App Group).
///
/// Aucune donnée n'est écrite en clair hors du groupe : les adresses `.onion`
/// y sont déjà publiques, la clé de publication n'existe pas sur l'appareil.
struct Magasin {
    static let groupe = "group.org.tordns.client"

    private enum Cle {
        static let coeur = "adresse.coeur"
        static let secours = "adresse.secours"
        static let communaute = "adresse.communaute"
        static let dnssec = "dnssec"
        static let dernierManifeste = "manifeste.version"
        static let adressesVerifiees = "manifeste.date"
    }

    private let defauts: UserDefaults

    init(groupe: String = Magasin.groupe) {
        defauts = UserDefaults(suiteName: groupe) ?? .standard
    }

    var coeur: String {
        get { defauts.string(forKey: Cle.coeur) ?? "" }
        nonmutating set { defauts.set(newValue, forKey: Cle.coeur) }
    }

    var secours: String {
        get { defauts.string(forKey: Cle.secours) ?? "" }
        nonmutating set { defauts.set(newValue, forKey: Cle.secours) }
    }

    var communaute: String {
        get { defauts.string(forKey: Cle.communaute) ?? "" }
        nonmutating set { defauts.set(newValue, forKey: Cle.communaute) }
    }

    var dnssec: Bool {
        get { defauts.bool(forKey: Cle.dnssec) }
        nonmutating set { defauts.set(newValue, forKey: Cle.dnssec) }
    }

    var versionManifeste: Int {
        defauts.integer(forKey: Cle.dernierManifeste)
    }

    var dateAdressesVerifiees: Date? {
        defauts.object(forKey: Cle.adressesVerifiees) as? Date
    }

    /// Adresse à utiliser : cœur, puis secours, puis communauté.
    var adresseActive: String {
        for candidate in [coeur, secours, communaute] where !candidate.isEmpty {
            return candidate
        }
        return ""
    }

    /// Télécharge `/maj/manifeste.json` et sa signature par Tor, les vérifie
    /// avec la clé épinglée, puis enregistre les adresses signées.
    ///
    /// L'App Store ne distribue pas le client iOS : le manifeste sert
    /// uniquement à la liste d'adresses, jamais à installer une mise à jour.
    @discardableResult
    func recupererAdresses(versionInstallee: Int64) throws -> [String: String] {
        let onion = adresseActive
        guard !onion.isEmpty else {
            throw ErreurTor(message: "aucune adresse configurée")
        }
        let manifeste = try PontTor.telecharger(
            onion: onion,
            chemin: "/maj/manifeste.json",
            maximum: 64 * 1024
        )
        let signature = try PontTor.telecharger(
            onion: onion,
            chemin: "/maj/manifeste.json.sig",
            maximum: 4096
        )
        let champs = try PontTor.verifierManifeste(
            manifeste: manifeste,
            signature: signature,
            versionInstallee: versionInstallee
        )
        for (nom, cle) in [("coeur", Cle.coeur), ("secours", Cle.secours), ("communaute", Cle.communaute)] {
            if let valeur = champs[nom], !valeur.isEmpty {
                defauts.set(valeur, forKey: cle)
            }
        }
        defauts.set(Int(champs["version"] ?? "0") ?? 0, forKey: Cle.dernierManifeste)
        defauts.set(Date(), forKey: Cle.adressesVerifiees)
        return champs
    }
}
