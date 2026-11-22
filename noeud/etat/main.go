// TorDNS — page d'état publique du nœud (Mission 8).
//
// Répond uniquement sur /.well-known/tordns/etat avec un JSON court : version
// du logiciel, état d'Unbound et de Tor, charge grossière. Aucun compteur de
// requêtes, aucun nom de domaine, aucun identifiant de client, aucun journal.
package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type etat struct {
	Logiciel string            `json:"logiciel"`
	Version  string            `json:"version"`
	Services map[string]string `json:"services"`
	Charge   string            `json:"charge"`
}

// classerCharge traduit la moyenne de charge (1 min) en trois niveaux
// grossiers. Les seuils visent un petit VPS, pas un serveur de calcul.
func classerCharge(moyenne float64) string {
	switch {
	case moyenne < 1:
		return "faible"
	case moyenne < 3:
		return "moyenne"
	default:
		return "forte"
	}
}

// lireCharge lit la moyenne 1 min de /proc/loadavg. Illisible : "inconnue".
func lireCharge(chemin string) string {
	brut, err := os.ReadFile(chemin)
	if err != nil {
		return "inconnue"
	}
	champs := strings.Fields(string(brut))
	if len(champs) == 0 {
		return "inconnue"
	}
	moyenne, err := strconv.ParseFloat(champs[0], 64)
	if err != nil {
		return "inconnue"
	}
	return classerCharge(moyenne)
}

// unboundJoignable ouvre une connexion TCP sur le résolveur. Une réponse DNS
// n'est pas nécessaire : le port qui accepte prouve que le service tourne.
func unboundJoignable(adresse string, delai time.Duration) bool {
	c, err := net.DialTimeout("tcp", adresse, delai)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// etatTor interroge le port de contrôle de Tor avec le cookie d'authentification
// et renvoie vrai si un circuit est établi.
func etatTor(adresse, cheminCookie string, delai time.Duration) bool {
	cookie, err := os.ReadFile(cheminCookie)
	if err != nil || len(cookie) == 0 {
		return false
	}
	c, err := net.DialTimeout("tcp", adresse, delai)
	if err != nil {
		return false
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(delai))
	_, err = fmt.Fprintf(c, "AUTHENTICATE %s\r\n", hex.EncodeToString(cookie))
	if err != nil {
		return false
	}
	reponse, err := lireReponse(c)
	if err != nil || !strings.HasPrefix(reponse, "250") {
		return false
	}
	_, err = fmt.Fprint(c, "GETINFO status/circuit-established\r\n")
	if err != nil {
		return false
	}
	reponse, err = lireReponse(c)
	if err != nil {
		return false
	}
	return strings.Contains(reponse, "status/circuit-established=1")
}

// lireReponse lit les lignes d'une réponse du port de contrôle jusqu'à la
// ligne finale. Une ligne de continuation est « 250-… » ; la dernière est
// « 250 … » (un espace au quatrième caractère).
func lireReponse(c net.Conn) (string, error) {
	var sb strings.Builder
	lecteur := bufio.NewReader(c)
	for {
		ligne, err := lecteur.ReadString('\n')
		sb.WriteString(ligne)
		if err != nil {
			return sb.String(), err
		}
		if len(ligne) >= 4 && ligne[3] == ' ' {
			return sb.String(), nil
		}
	}
}

func etatCourant(version, unbound, controleTor, cookie string) etat {
	const delai = 2 * time.Second
	services := map[string]string{
		"unbound": "indisponible",
		"tor":     "indisponible",
	}
	if unboundJoignable(unbound, delai) {
		services["unbound"] = "ok"
	}
	if etatTor(controleTor, cookie, delai) {
		services["tor"] = "ok"
	}
	return etat{
		Logiciel: "TorDNS",
		Version:  version,
		Services: services,
		Charge:   lireCharge("/proc/loadavg"),
	}
}

func main() {
	version := os.Getenv("TORDNS_VERSION")
	if version == "" {
		version = "inconnue"
	}
	unbound := os.Getenv("UNBOUND_ADDR")
	if unbound == "" {
		unbound = "unbound:5335"
	}
	controleTor := os.Getenv("TORDNS_CONTROLE_TOR")
	if controleTor == "" {
		controleTor = "tor:9051"
	}
	cookie := os.Getenv("TORDNS_COOKIE_TOR")
	if cookie == "" {
		cookie = "/tor/control_auth_cookie"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/tordns/etat", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "méthode non autorisée", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if r.Method == http.MethodHead {
			return
		}
		_ = json.NewEncoder(w).Encode(etatCourant(version, unbound, controleTor, cookie))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})

	serveur := &http.Server{
		Addr:              ":8081",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		// Journaux explicitement jetés : aucun accès, aucune erreur écrite.
		ErrorLog: log.New(io.Discard, "", 0),
	}
	_ = serveur.ListenAndServe()
}
