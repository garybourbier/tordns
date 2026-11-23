// Liste d'adresses signée (mission 12).
//
// Le client lit le dernier manifeste vérifié déposé par tordns-client-maj et
// choisit le cœur ou la communauté selon le réglage utilisateur. Une liste
// absente, expirée ou mal signée ne fait jamais échouer le client : l'adresse
// saisie en configuration reste le secours.
package main

import (
	"os"
	"path/filepath"
	"strings"
	"time"

	"tordns/manifeste"
)

// modeAdresse vaut « coeur » (défaut), « secours » ou « communaute ».
func choisirAdresse(mode string, adresses map[string]string, secours string) string {
	coeur := adresses["coeur"]
	communaute := adresses["communaute"]
	switch mode {
	case "communaute":
		if communaute != "" {
			return communaute
		}
		if coeur != "" {
			return coeur
		}
	case "secours":
		if coeur != "" {
			return coeur
		}
		if communaute != "" {
			return communaute
		}
	default:
		// « cœur seulement » ne bascule jamais silencieusement sur un bénévole.
		if coeur != "" {
			return coeur
		}
	}
	return secours
}

// adressesVerifiees retourne les adresses du manifeste si sa signature et sa
// date sont valides. Aucun nom de requête n'est lu ni journalisé.
func adressesVerifiees(dossier, cle string, maintenant time.Time) map[string]string {
	chemin := filepath.Join(dossier, "manifeste.json")
	signature := filepath.Join(dossier, "manifeste.json.sig")
	m, err := manifeste.VerifierFichiers(chemin, signature, cle, maintenant)
	if err != nil {
		return nil
	}
	return m.Adresses
}

// adresseEffective combine la liste signée, le mode et l'adresse de secours.
func adresseEffective(dossier, cle, mode, secours string) string {
	if mode == "" {
		mode = "coeur"
	}
	return choisirAdresse(mode, adressesVerifiees(dossier, cle, time.Now()), secours)
}

// dossierAdresses est le chemin par défaut, écrit par la mise à jour Linux.
func dossierAdresses() string {
	return filepath.Join("/var/lib/tordns", "maj")
}

// clePublique lit la clé de publication surchargeable (tests, rotation).
func clePublique() string {
	if v := os.Getenv("TORDNS_MAJ_CLE"); v != "" {
		return v
	}
	return manifeste.ClePubliqueEpinglee
}

func modeValide(mode string) bool {
	switch strings.ToLower(mode) {
	case "coeur", "secours", "communaute":
		return true
	}
	return false
}
