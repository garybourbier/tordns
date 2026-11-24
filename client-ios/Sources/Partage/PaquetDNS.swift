import Foundation

/// Datagramme DNS lu sur le tunnel : en-tête IPv4 + UDP.
///
/// Le tunnel n'annonce qu'un serveur DNS IPv4, et le port 53 en UDP suffit aux
/// résolveurs d'iOS. Un paquet IPv6, TCP ou d'un autre port est refusé : il
/// est alors abandonné plutôt que relayé, pour ne jamais laisser fuir une
/// requête hors de Tor.
struct DatagrammeDNS {
    static let portDNS: UInt16 = 53

    let source: [UInt8]
    let destination: [UInt8]
    let sourcePort: UInt16
    let destinationPort: UInt16
    let charge: [UInt8]

    /// Analyse un paquet IP. Rend nil si ce n'est pas de l'IPv4/UDP vers le
    /// port 53.
    init?(paquet: Data) {
        let octets = [UInt8](paquet)
        guard octets.count >= 28, octets[0] >> 4 == 4 else { return nil }
        let tailleEntete = Int(octets[0] & 0x0f) * 4
        guard tailleEntete >= 20, octets.count >= tailleEntete + 8 else { return nil }
        guard octets[9] == 17 else { return nil }  // UDP
        let longueurIP = Int(octets[2]) << 8 | Int(octets[3])
        guard longueurIP >= tailleEntete + 8, longueurIP <= octets.count else { return nil }

        source = Array(octets[12..<16])
        destination = Array(octets[16..<20])
        let udp = tailleEntete
        sourcePort = UInt16(octets[udp]) << 8 | UInt16(octets[udp + 1])
        destinationPort = UInt16(octets[udp + 2]) << 8 | UInt16(octets[udp + 3])
        let longueurUDP = Int(octets[udp + 4]) << 8 | Int(octets[udp + 5])
        let fin = min(udp + max(longueurUDP, 8), longueurIP)
        charge = Array(octets[(udp + 8)..<fin])
        guard destinationPort == DatagrammeDNS.portDNS, !charge.isEmpty else { return nil }
    }

    /// Construit le datagramme de réponse : adresses et ports inversés.
    func repondre(_ charge: [UInt8]) -> Data {
        var paquet = [UInt8]()
        paquet.reserveCapacity(28 + charge.count)
        let longueurTotale = 20 + 8 + charge.count

        paquet.append(0x45)                       // IPv4, en-tête de 20 octets
        paquet.append(0x00)                       // DSCP
        paquet.append(UInt8((longueurTotale >> 8) & 0xff))
        paquet.append(UInt8(longueurTotale & 0xff))
        paquet.append(0x00)                       // identification
        paquet.append(0x00)
        paquet.append(0x40)                       // ne pas fragmenter
        paquet.append(0x00)
        paquet.append(64)                         // TTL
        paquet.append(17)                         // UDP
        paquet.append(0x00)                       // somme de contrôle, remplie plus bas
        paquet.append(0x00)
        paquet.append(contentsOf: destination)    // expéditeur = ancien destinataire
        paquet.append(contentsOf: source)         // destinataire = ancien expéditeur
        let somme = PaquetDNS.sommeEntete(paquet)
        paquet[10] = UInt8((somme >> 8) & 0xff)
        paquet[11] = UInt8(somme & 0xff)

        paquet.append(UInt8((destinationPort >> 8) & 0xff))
        paquet.append(UInt8(destinationPort & 0xff))
        paquet.append(UInt8((sourcePort >> 8) & 0xff))
        paquet.append(UInt8(sourcePort & 0xff))
        let longueurUDP = 8 + charge.count
        paquet.append(UInt8((longueurUDP >> 8) & 0xff))
        paquet.append(UInt8(longueurUDP & 0xff))
        paquet.append(0x00)                       // somme UDP nulle : admise en IPv4
        paquet.append(0x00)
        paquet.append(contentsOf: charge)
        return Data(paquet)
    }
}

enum PaquetDNS {
    /// Somme de contrôle d'en-tête IPv4, telle que décrite par la RFC 791.
    static func sommeEntete(_ entete: [UInt8]) -> UInt16 {
        var somme: UInt32 = 0
        var index = 0
        while index + 1 < entete.count {
            somme += UInt32(entete[index]) << 8 | UInt32(entete[index + 1])
            index += 2
        }
        if index < entete.count {
            somme += UInt32(entete[index]) << 8
        }
        while somme >> 16 != 0 {
            somme = (somme & 0xffff) + (somme >> 16)
        }
        return ~UInt16(somme & 0xffff)
    }

    /// Identifiant de requête DNS, utilisé pour apparier les réponses.
    static func identifiant(_ message: [UInt8]) -> UInt16? {
        guard message.count >= 12 else { return nil }
        return UInt16(message[0]) << 8 | UInt16(message[1])
    }
}
