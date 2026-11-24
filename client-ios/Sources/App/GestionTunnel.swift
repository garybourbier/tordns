import NetworkExtension

/// Pilote le tunnel DNS depuis l'application : active, désactive et lit son
/// état. Aucune configuration de profil n'est écrite ici ; iOS demande à
/// l'utilisateur l'autorisation « VPN » au premier démarrage.
@MainActor
final class GestionTunnel: ObservableObject {
    enum Etat: String {
        case inactif = "inactif"
        case demarrage = "démarrage"
        case actif = "actif"
        case erreur = "erreur"

        var libelle: String {
            switch self {
            case .inactif: return "Inactif"
            case .demarrage: return "Démarrage…"
            case .actif: return "Actif"
            case .erreur: return "Erreur"
            }
        }
    }

    @Published private(set) var etat: Etat = .inactif
    @Published private(set) var message: String = ""

    private var gestionnaire: NETunnelProviderManager?

    func charger() async {
        do {
            let gestionnaires = try await NETunnelProviderManager.loadAllFromPreferences()
            gestionnaire = gestionnaires.first
            etat = Self.etat(de: gestionnaire)
        } catch {
            etat = .erreur
            message = error.localizedDescription
        }
    }

    func activer(onion: String) async {
        guard !onion.isEmpty else {
            etat = .erreur
            message = "Renseignez d'abord une adresse TorDNS."
            return
        }
        do {
            etat = .demarrage
            let gestionnaire = try await prepare()
            try gestionnaire.connection.startVPNTunnel(options: ["onion": onion as NSObject])
            etat = .actif
            message = ""
        } catch {
            etat = .erreur
            message = error.localizedDescription
        }
    }

    func desactiver() {
        gestionnaire?.connection.stopVPNTunnel()
        etat = .inactif
    }

    /// Crée la configuration du tunnel si elle n'existe pas encore, puis
    /// enregistre les réglages (identifiant de l'extension, nom affiché).
    private func prepare() async throws -> NETunnelProviderManager {
        let gestionnaire = try await NETunnelProviderManager.loadAllFromPreferences().first
            ?? NETunnelProviderManager()
        let protocole = NETunnelProviderProtocol()
        protocole.providerBundleIdentifier = "org.tordns.client.ios.tunnel"
        protocole.serverAddress = "TorDNS"
        protocole.providerConfiguration = ["usage": "dns"]
        gestionnaire.protocolConfiguration = protocole
        gestionnaire.localizedDescription = "TorDNS"
        gestionnaire.isEnabled = true
        try await gestionnaire.saveToPreferences()
        try await gestionnaire.loadFromPreferences()
        self.gestionnaire = gestionnaire
        return gestionnaire
    }

    private static func etat(de gestionnaire: NETunnelProviderManager?) -> Etat {
        guard let connexion = gestionnaire?.connection else { return .inactif }
        switch connexion.status {
        case .connected: return .actif
        case .connecting, .reasserting: return .demarrage
        case .disconnecting: return .demarrage
        default: return .inactif
        }
    }
}
