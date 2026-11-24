import SwiftUI

/// Écran unique : marche/arrêt, adresses, état DNSSEC et test de fuite.
struct VuePrincipale: View {
    @StateObject private var tunnel = GestionTunnel()
    @State private var magasin = Magasin()
    @State private var coeur = ""
    @State private var secours = ""
    @State private var communaute = ""
    @State private var resultatTest = ""
    @State private var enCours = false

    var body: some View {
        NavigationStack {
            Form {
                Section("État") {
                    LabeledContent("Tunnel", value: tunnel.etat.libelle)
                    if !tunnel.message.isEmpty {
                        Text(tunnel.message).foregroundStyle(.red)
                    }
                    Toggle("Tunnel DNS actif", isOn: Binding(
                        get: { tunnel.etat == .actif },
                        set: { actif in
                            Task {
                                if actif {
                                    await tunnel.activer(onion: magasin.adresseActive)
                                } else {
                                    tunnel.desactiver()
                                }
                            }
                        }
                    ))
                }

                Section("Adresses TorDNS") {
                    TextField("cœur (.onion)", text: $coeur)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    TextField("secours (.onion)", text: $secours)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    TextField("communauté (.onion)", text: $communaute)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    Button("Enregistrer") {
                        magasin.coeur = coeur
                        magasin.secours = secours
                        magasin.communaute = communaute
                    }
                    Button("Vérifier la liste signée") {
                        Task { await verifierListe() }
                    }
                    .disabled(enCours || magasin.adresseActive.isEmpty)
                    if let date = magasin.dateAdressesVerifiees {
                        LabeledContent(
                            "Liste vérifiée",
                            value: date.formatted(date: .abbreviated, time: .shortened)
                        )
                        LabeledContent("Version du manifeste", value: "\(magasin.versionManifeste)")
                    }
                }

                Section("DNSSEC") {
                    Toggle("Exiger DNSSEC", isOn: Binding(
                        get: { magasin.dnssec },
                        set: { magasin.dnssec = $0 }
                    ))
                    Text("Les zones signées sont vérifiées par le relais ; les zones non signées restent servies, comme sur les autres clients.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }

                Section("Test de fuite") {
                    Button("Tester") {
                        Task { await testerFuite() }
                    }
                    .disabled(enCours || magasin.adresseActive.isEmpty)
                    if !resultatTest.isEmpty {
                        Text(resultatTest).font(.footnote)
                    }
                }

                Section("Mémoire") {
                    LabeledContent("Processus", value: Diagnostic.memoireLisible() ?? "inconnue")
                    Text("L'extension réseau d'iOS dispose d'environ 50 Mo ; la mesure se fait dans l'extension, pas ici.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
            .navigationTitle("TorDNS")
            .task {
                coeur = magasin.coeur
                secours = magasin.secours
                communaute = magasin.communaute
                await tunnel.charger()
            }
        }
    }

    /// Récupère le manifeste signé par Tor et enregistre les adresses qu'il
    /// contient. Aucune mise à jour d'application n'est possible hors App
    /// Store : le manifeste ne sert qu'à la liste d'adresses.
    private func verifierListe() async {
        enCours = true
        defer { enCours = false }
        do {
            let repertoires = try PontTor.repertoires()
            try await demarrerTor(siBesoin: repertoires)
            let champs = try magasin.recupererAdresses(versionInstallee: Diagnostic.versionInstallee)
            coeur = magasin.coeur
            secours = magasin.secours
            communaute = magasin.communaute
            resultatTest = "Liste signée acceptée (version \(champs["version"] ?? "?"))"
        } catch {
            resultatTest = "Liste refusée : \(error.localizedDescription)"
        }
    }

    /// Envoie une requête à un nom aléatoire : une réponse signifie que le
    /// chemin DNS passe par Tor ; aucune requête ne part ailleurs.
    private func testerFuite() async {
        enCours = true
        defer { enCours = false }
        do {
            let repertoires = try PontTor.repertoires()
            try await demarrerTor(siBesoin: repertoires)
            let nom = "test-\(UUID().uuidString.prefix(8).lowercased()).tordns"
            let reponse = try PontTor.doh(
                onion: magasin.adresseActive,
                requete: Diagnostic.requeteDNS(nom: nom),
                delai: 8
            )
            let rcode = reponse.count >= 4 ? reponse[3] & 0x0f : 15
            resultatTest = rcode == 3
                ? "Aucune fuite : \(nom) est passé par Tor (NXDOMAIN attendu)."
                : "Réponse reçue par Tor, rcode \(rcode)."
        } catch {
            resultatTest = "Échec du test : \(error.localizedDescription)"
        }
    }

    private func demarrerTor(siBesoin repertoires: (etat: URL, cache: URL)) async throws {
        guard !PontTor.demarre else { return }
        try await withCheckedThrowingContinuation { (suite: CheckedContinuation<Void, Error>) in
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    try PontTor.demarrer(etat: repertoires.etat, cache: repertoires.cache)
                    suite.resume()
                } catch {
                    suite.resume(throwing: error)
                }
            }
        }
    }
}
