package main

// Diagnostic des fuites DNS, sans envoyer de requête ni journaliser de nom de
// domaine. Chaque constat indique quoi fermer. Les chemins sont relatifs à une
// racine injectable pour que les tests simulent une machine qui fuit puis une
// machine corrigée.

import (
	"net"
	"os"
	"path/filepath"
	"strings"
)

type constat struct {
	fuite bool
	texte string
}

func diagnosticer(racine string) []constat {
	var constats []constat
	resolv := filepath.Join(racine, "etc", "resolv.conf")
	donnees, err := os.ReadFile(resolv)
	if err != nil {
		constats = append(constats, constat{true,
			"/etc/resolv.conf illisible : le résolveur système échappe au diagnostic. Vérifier manuellement."})
	} else {
		vu := false
		for _, ligne := range strings.Split(string(donnees), "\n") {
			champs := strings.Fields(ligne)
			if len(champs) < 2 || champs[0] != "nameserver" {
				continue
			}
			vu = true
			ip := net.ParseIP(strings.Trim(champs[1], "[]"))
			switch {
			case ip == nil:
				constats = append(constats, constat{true,
					"resolv.conf : résolveur « " + champs[1] + " » illisible. Utiliser 127.0.0.1."})
			case ip.Equal(net.IPv4(127, 0, 0, 1)):
				constats = append(constats, constat{false,
					"resolv.conf utilise 127.0.0.1 (TorDNS)."})
			case ip.Equal(net.IPv6loopback):
				constats = append(constats, constat{true,
					"resolv.conf utilise ::1, que TorDNS n'écoute pas par défaut : " +
						"utiliser 127.0.0.1 ou lancer le client avec -ecoute [::1]:53."})
			case ip.Equal(net.IPv4(127, 0, 0, 53)):
				constats = append(constats, constat{true,
					"resolv.conf pointe vers 127.0.0.53 (systemd-resolved), qui contourne TorDNS : " +
						"désactiver DNSStubListener ou remplacer par 127.0.0.1."})
			default:
				constats = append(constats, constat{true,
					"resolv.conf utilise le résolveur " + champs[1] + ", hors TorDNS : " +
						"le remplacer par « nameserver 127.0.0.1 »."})
			}
		}
		if !vu {
			constats = append(constats, constat{true,
				"resolv.conf ne déclare aucun résolveur : les applications peuvent fuir. " +
					"Ajouter « nameserver 127.0.0.1 »."})
		}
	}

	// systemd-resolved peut être actif sans que resolv.conf le montre (symlink
	// ou clients qui parlent directement au stub).
	cible, _ := os.Readlink(resolv)
	if strings.Contains(cible, "systemd") {
		constats = append(constats, constat{true,
			"/etc/resolv.conf pointe vers systemd-resolved (" + cible + ") : " +
				"désactiver DNSStubListener ou configurer le stub vers 127.0.0.1."})
	} else if _, err := os.Stat(filepath.Join(racine, "run", "systemd", "resolve", "stub-resolv.conf")); err == nil {
		constats = append(constats, constat{true,
			"systemd-resolved actif (stub 127.0.0.53) : les clients qui l'interrogent contournent TorDNS. " +
				"Désactiver DNSStubListener ou le configurer vers 127.0.0.1."})
	}

	// DoH des navigateurs : seules les politiques d'entreprise sont
	// inspectables sans lire les profils privés. Le reste est signalé.
	politiques := []string{
		filepath.Join(racine, "etc", "firefox", "policies", "policies.json"),
		filepath.Join(racine, "etc", "chromium", "policies", "managed"),
		filepath.Join(racine, "etc", "opt", "chrome", "policies", "managed"),
	}
	trouveDoH := false
	for _, chemin := range politiques {
		for _, fichier := range fichiersJSON(chemin) {
			contenu, err := os.ReadFile(fichier)
			if err != nil {
				continue
			}
			bas := strings.ToLower(string(contenu))
			if strings.Contains(bas, "dnsoverhttps") || strings.Contains(bas, "network.trr.mode") {
				trouveDoH = true
				desactive := strings.Contains(bas, `"off"`) || strings.Contains(bas, `"mode":5`) ||
					strings.Contains(bas, `"mode": 5`)
				if desactive {
					constats = append(constats, constat{false,
						"politique DoH désactivée dans " + fichier + "."})
				} else {
					constats = append(constats, constat{true,
						"politique DoH active dans " + fichier + " : la désactiver " +
							"(DnsOverHttpsMode=off, network.trr.mode=5) pour passer par TorDNS."})
				}
			}
		}
	}
	if !trouveDoH {
		constats = append(constats, constat{false,
			"aucune politique DoH d'entreprise détectée ; le DoH intégré aux profils " +
				"navigateur n'est pas lisible de façon fiable : le désactiver dans les réglages " +
				"(Firefox : « Résolution DNS via HTTPS » sur désactivé ; Chrome/Edge : « DNS sécurisé » sur désactivé)."})
	}
	return constats
}

func fichiersJSON(chemin string) []string {
	infos, err := os.ReadDir(chemin)
	if err != nil {
		if _, err := os.Stat(chemin); err == nil {
			return []string{chemin}
		}
		return nil
	}
	var fichiers []string
	for _, info := range infos {
		if !info.IsDir() && strings.HasSuffix(info.Name(), ".json") {
			fichiers = append(fichiers, filepath.Join(chemin, info.Name()))
		}
	}
	return fichiers
}

// afficherDiagnostic écrit les constats et renvoie le nombre de fuites.
func afficherDiagnostic(constats []constat) int {
	fuites := 0
	for _, c := range constats {
		etiquette := "OK"
		if c.fuite {
			etiquette = "FUITE"
			fuites++
		}
		os.Stdout.WriteString("[" + etiquette + "] " + c.texte + "\n")
	}
	if fuites == 0 {
		os.Stdout.WriteString("Bilan : aucune fuite détectée.\n")
	} else {
		os.Stdout.WriteString("Bilan : " + itoa(fuites) + " fuite(s) à fermer.\n")
	}
	return fuites
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}
