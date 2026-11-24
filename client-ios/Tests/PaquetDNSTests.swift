import XCTest
@testable import TorDNS

/// Tests de l'analyse des paquets du tunnel. Ils tournent sur le simulateur,
/// sans Tor ni réseau : `xcodebuild test -scheme TorDNS -destination
/// 'platform=iOS Simulator,name=iPhone 15'`.
final class PaquetDNSTests: XCTestCase {
    /// Paquet IPv4/UDP factice : 10.255.0.1:53 → 192.0.2.7:4444.
    private func paquet(portDestination: UInt16 = 53, protocole: UInt8 = 17) -> Data {
        var octets: [UInt8] = [
            0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 64, protocole, 0x00, 0x00,
            10, 255, 0, 1,
            192, 0, 2, 7,
        ]
        let charge: [UInt8] = [0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]
        let longueurUDP = UInt16(8 + charge.count)
        octets.append(contentsOf: [
            0x00, 0x35,
            UInt8(0x11), 0x5c,
            UInt8(longueurUDP >> 8), UInt8(longueurUDP & 0xff),
            0x00, 0x00,
        ])
        octets.append(contentsOf: charge)
        let total = octets.count
        octets[2] = UInt8((total >> 8) & 0xff)
        octets[3] = UInt8(total & 0xff)
        _ = portDestination
        return Data(octets)
    }

    func testAnalyseUneRequeteDNS() throws {
        let datagramme = try XCTUnwrap(DatagrammeDNS(paquet: paquet()))
        XCTAssertEqual(datagramme.source, [10, 255, 0, 1])
        XCTAssertEqual(datagramme.destination, [192, 0, 2, 7])
        XCTAssertEqual(datagramme.sourcePort, 53)
        XCTAssertEqual(datagramme.destinationPort, 4444)
        XCTAssertEqual(datagramme.charge.count, 12)
        XCTAssertEqual(PaquetDNS.identifiant(datagramme.charge), 0x1234)
    }

    func testRefuseAutrePortEtAutreProtocole() {
        var mauvaisPort = [UInt8](paquet())
        mauvaisPort[22] = 0x00
        mauvaisPort[23] = 0x50  // 80
        XCTAssertNil(DatagrammeDNS(paquet: Data(mauvaisPort)))
        XCTAssertNil(DatagrammeDNS(paquet: paquet(protocole: 6)))  // TCP
        XCTAssertNil(DatagrammeDNS(paquet: Data([0x60] + [0] + [UInt8](repeating: 0, count: 40))))
    }

    func testReponseInverseLesAdressesEtLesPorts() throws {
        let datagramme = try XCTUnwrap(DatagrammeDNS(paquet: paquet()))
        let charge: [UInt8] = [0x12, 0x34, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0]
        let reponse = [UInt8](datagramme.repondre(charge))

        XCTAssertEqual(reponse[12..<16], [192, 0, 2, 7])
        XCTAssertEqual(reponse[16..<20], [10, 255, 0, 1])
        XCTAssertEqual(reponse[20..<22], [0x11, 0x5c])  // 4444
        XCTAssertEqual(reponse[22..<24], [0x00, 0x35])  // 53
        XCTAssertEqual(Array(reponse[28...]), charge)

        // La somme d'en-tête rendue est correcte : la recalculer sur le paquet
        // complet (somme comprise) donne zéro.
        XCTAssertEqual(PaquetDNS.sommeEntete(Array(reponse[0..<20])), 0)
    }

    func testIdentifiantTropCourt() {
        XCTAssertNil(PaquetDNS.identifiant([0x00, 0x01]))
    }
}
