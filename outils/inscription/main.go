// TorDNS — inscription d'un nœud au registre communautaire (Mission 10).
//
// Envoie l'adresse d'instance au registre (par Tor), écrit le défi reçu dans
// le fichier servi par le nœud, puis demande la vérification. Aucun secret,
// aucun nom de domaine, aucun journal de requête DNS.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type reponse struct {
	Etat      string `json:"etat"`
	Adresse   string `json:"adresse"`
	Defi      string `json:"defi"`
	Page      string `json:"page"`
	Message   string `json:"message"`
	Quarantai int64  `json:"quarantaine_secondes"`
}

func clientHTTP(socks string) (*http.Client, error) {
	t := &http.Transport{}
	if socks != "" {
		u, err := url.Parse("socks5://" + socks)
		if err != nil {
			return nil, fmt.Errorf("proxy SOCKS invalide : %w", err)
		}
		t.Proxy = http.ProxyURL(u)
	}
	return &http.Client{Transport: t, Timeout: 60 * time.Second}, nil
}

func poster(client *http.Client, base, chemin string, corps any, sortie any) (int, error) {
	brut, err := json.Marshal(corps)
	if err != nil {
		return 0, err
	}
	rep, err := client.Post(strings.TrimRight(base, "/")+chemin, "application/json", bytes.NewReader(brut))
	if err != nil {
		return 0, err
	}
	defer rep.Body.Close()
	data, err := io.ReadAll(io.LimitReader(rep.Body, 65536))
	if err != nil {
		return rep.StatusCode, err
	}
	if rep.StatusCode/100 != 2 {
		var e struct {
			Erreur string `json:"erreur"`
		}
		_ = json.Unmarshal(data, &e)
		if e.Erreur == "" {
			e.Erreur = strings.TrimSpace(string(data))
		}
		return rep.StatusCode, fmt.Errorf("registre : HTTP %d : %s", rep.StatusCode, e.Erreur)
	}
	if err := json.Unmarshal(data, sortie); err != nil {
		return rep.StatusCode, fmt.Errorf("réponse du registre illisible : %w", err)
	}
	return rep.StatusCode, nil
}

// ecrireDefi remplace le défi atomiquement : le nœud ne sert jamais un
// fichier partiel.
func ecrireDefi(chemin, defi string) error {
	if chemin == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(chemin), 0o700); err != nil {
		return err
	}
	tmp := chemin + ".tmp"
	if err := os.WriteFile(tmp, []byte(defi+"\n"), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, chemin)
}

func executer(registre, adresse, contact, defiChemin, socks string) (reponse, error) {
	if registre == "" || adresse == "" {
		return reponse{}, errors.New("-registre et -adresse sont obligatoires")
	}
	client, err := clientHTTP(socks)
	if err != nil {
		return reponse{}, err
	}
	var premiere reponse
	_, err = poster(client, registre, "/inscription", map[string]string{
		"adresse_instance":   adresse,
		"contact_facultatif": contact,
	}, &premiere)
	if err != nil {
		return reponse{}, err
	}
	if premiere.Defi == "" {
		return reponse{}, errors.New("le registre n'a pas renvoyé de défi")
	}
	if err := ecrireDefi(defiChemin, premiere.Defi); err != nil {
		return reponse{}, fmt.Errorf("écriture du défi : %w", err)
	}
	var seconde reponse
	if _, err := poster(client, registre, "/inscription/confirmer", map[string]string{
		"adresse_instance": adresse,
	}, &seconde); err != nil {
		return reponse{}, err
	}
	if seconde.Page == "" {
		seconde.Page = premiere.Page
	}
	return seconde, nil
}

func main() {
	registre := flag.String("registre", "", "URL HTTP du registre (service caché)")
	adresse := flag.String("adresse", "", "adresse .onion d'instance du nœud")
	contact := flag.String("contact", "", "contact facultatif (jamais publié)")
	defiChemin := flag.String("defi", "", "fichier de défi servi par le nœud")
	socks := flag.String("socks", "127.0.0.1:9050", "proxy SOCKS pour joindre Tor (vide : direct)")
	flag.Parse()

	reponse, err := executer(*registre, *adresse, *contact, *defiChemin, *socks)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERREUR : %v\n", err)
		os.Exit(1)
	}
	if reponse.Etat != "confirme" {
		fmt.Fprintf(os.Stderr, "ERREUR : état inattendu : %q\n", reponse.Etat)
		os.Exit(1)
	}
	fmt.Printf("OK : défi vérifié par le registre pour %s\n", adresseVide(reponse.Adresse, *adresse))
	fmt.Printf("Quarantaine : %d s de sondes avant admission.\n", reponse.Quarantai)
	if reponse.Page != "" {
		fmt.Printf("Page publique : %s\n", reponse.Page)
	}
	fmt.Println("L'admission n'est jamais automatique dans le pool cœur ; ce nœud ne peut entrer que dans le pool communauté.")
}

func adresseVide(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
