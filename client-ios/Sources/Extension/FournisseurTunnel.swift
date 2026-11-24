import NetworkExtension
import os

/// Extension réseau : un tunnel de paquets réduit au DNS.
///
/// Le tunnel n'achemine aucun trafic IP général : il annonce un unique
/// serveur DNS (10.255.0.1) et ne reçoit que les requêtes des applications
/// vers ce serveur, port 53 en UDP. Chaque requête part en DoH par un circuit
/// Tor ; une requête qui ne peut pas l'être est abandonnée, jamais envoyée en
/// clair. C'est le choix documenté dans `project.yml` et le README : le proxy
/// DNS d'Apple (`NEDNSProxyProvider`) exige un appareil supervisé et un profil
/// MDM, donc il ne peut pas servir une application grand public.
final class FournisseurTunnel: NEPacketTunnelProvider {
    private static let adresseDNS = "10.255.0.1"
    private let magasin = Magasin()
    private let requetes = DispatchQueue(label: "org.tordns.ios.dns")
    private let journal = Logger(subsystem: "org.tordns.client.ios", category: "tunnel")
    private var actif = false

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        let onion = (options?["onion"] as? String) ?? magasin.adresseActive
        guard !onion.isEmpty else {
            completionHandler(ErreurTor(message: "aucune adresse TorDNS configurée"))
            return
        }
        guard let reseau = tunnelReseau() else {
            completionHandler(ErreurTor(message: "réglages réseau refusés"))
            return
        }

        setTunnelNetworkSettings(reseau) { [weak self] erreur in
            guard let self else { return }
            if let erreur {
                completionHandler(erreur)
                return
            }
            // Le bootstrap Arti dure 20 à 90 s : il bloque un fil dédié, pas
            // la file principale de l'extension.
            self.requetes.async {
                do {
                    let repertoires = try PontTor.repertoires()
                    try PontTor.demarrer(etat: repertoires.etat, cache: repertoires.cache)
                    self.actif = true
                    self.journal.notice("Tor prêt, tunnel DNS actif")
                    completionHandler(nil)
                    self.lirePaquets(onion: onion)
                } catch {
                    self.journal.error("bootstrap Tor impossible")
                    completionHandler(error)
                }
            }
        }
    }

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        actif = false
        PontTor.arreter()
        completionHandler()
    }

    /// Tunnel IPv4 + DNS. Aucune route par défaut n'est incluse : le trafic
    /// des applications continue de sortir normalement, seul le DNS passe ici.
    private func tunnelReseau() -> NEPacketTunnelNetworkSettings? {
        let reseau = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: Self.adresseDNS)

        let ipv4 = NEIPv4Settings(
            addresses: [Self.adresseDNS],
            subnetMasks: ["255.255.255.255"]
        )
        ipv4.includedRoutes = []
        ipv4.excludedRoutes = [NEIPv4Route.default()]
        reseau.ipv4Settings = ipv4

        let dns = NEDNSSettings(servers: [Self.adresseDNS])
        dns.matchDomains = [""]  // tous les domaines, y compris les recherches simples
        reseau.dnsSettings = dns
        reseau.mtu = 1500
        return reseau
    }

    private func lirePaquets(onion: String) {
        guard actif else { return }
        packetFlow.readPackets { [weak self] paquets, protocoles in
            guard let self, self.actif else { return }
            self.requetes.async {
                var reponses: [Data] = []
                for (index, paquet) in paquets.enumerated() where index < protocoles.count {
                    guard protocoles[index].int32Value == AF_INET,
                          let datagramme = DatagrammeDNS(paquet: paquet)
                    else { continue }
                    if let reponse = self.resoudre(datagramme, onion: onion) {
                        reponses.append(reponse)
                    }
                }
                if !reponses.isEmpty {
                    self.packetFlow.writePackets(reponses, withProtocols: reponses.map {
                        NSNumber(value: AF_INET)
                    })
                }
                self.lirePaquets(onion: onion)
            }
        }
    }

    private func resoudre(_ datagramme: DatagrammeDNS, onion: String) -> Data? {
        do {
            let reponse = try PontTor.doh(
                onion: onion,
                requete: Data(datagramme.charge),
                delai: 5
            )
            guard reponse.count >= 12 else {
                journal.error("réponse DoH trop courte")
                return nil
            }
            return datagramme.repondre([UInt8](reponse))
        } catch {
            // Aucun repli en clair : la requête est perdue, le résolveur
            // d'iOS la retentera par le même chemin.
            journal.error("DoH impossible, requête abandonnée")
            return nil
        }
    }
}
