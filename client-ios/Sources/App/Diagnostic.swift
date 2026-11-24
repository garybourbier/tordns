import Foundation

/// Mesures et utilitaires locaux, sans réseau ni journal de requêtes.
enum Diagnostic {
    /// Version installée au format du manifeste : 0.8.0 → 800.
    static var versionInstallee: Int64 {
        let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0"
        let morceaux = version.split(separator: ".").compactMap { Int($0) }
        let majeur = morceaux.count > 0 ? morceaux[0] : 0
        let mineur = morceaux.count > 1 ? morceaux[1] : 0
        let correctif = morceaux.count > 2 ? morceaux[2] : 0
        return Int64(majeur * 10000 + mineur * 100 + correctif)
    }

    /// Empreinte mémoire du processus (`phys_footprint`), en octets.
    ///
    /// À appeler dans l'extension pour comparer la consommation d'Arti aux
    /// ~50 Mo accordés par iOS à une extension réseau.
    static func memoire() -> Int64? {
        var info = task_vm_info_data_t()
        var compte = mach_msg_type_number_t(
            MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<natural_t>.size
        )
        let resultat = withUnsafeMutablePointer(to: &info) { pointeur in
            pointeur.withMemoryRebound(to: integer_t.self, capacity: Int(compte)) { rebondi in
                task_info(
                    mach_task_self_,
                    task_flavor_t(TASK_VM_INFO),
                    rebondi,
                    &compte
                )
            }
        }
        guard resultat == KERN_SUCCESS else { return nil }
        return Int64(info.phys_footprint)
    }

    static func memoireLisible() -> String? {
        guard let octets = memoire() else { return nil }
        return ByteCountFormatter.string(fromByteCount: octets, countStyle: .memory)
    }

    /// Requête DNS A pour un nom, identifiant aléatoire.
    static func requeteDNS(nom: String) -> Data {
        var requete = [UInt8]()
        var graine = UInt16.random(in: 1...UInt16.max)
        requete.append(UInt8(graine >> 8))
        requete.append(UInt8(graine & 0xff))
        graine = 0x0100  // récursion demandée
        requete.append(UInt8(graine >> 8))
        requete.append(UInt8(graine & 0xff))
        requete.append(contentsOf: [0, 1, 0, 0, 0, 0, 0, 0])
        for partie in nom.split(separator: ".") {
            requete.append(UInt8(partie.utf8.count))
            requete.append(contentsOf: partie.utf8)
        }
        requete.append(0)
        requete.append(contentsOf: [0, 1, 0, 1])
        return Data(requete)
    }
}
