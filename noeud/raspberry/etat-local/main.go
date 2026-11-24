// TorDNS — page d'état locale du nœud (Mission 24).
//
// Répond sur http://tordns.local (mDNS, avahi) avec l'essentiel : nœud en
// ligne, adresse d'instance, inscription au registre communauté en
// quarantaine ou admise, état des mises à jour. La page ne lit que des
// fichiers locaux et l'état du service tordns : aucun nom de domaine, aucune
// requête DNS, aucun identifiant de client, aucun journal.
package main

import (
	"encoding/json"
	"flag"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Etat est ce que la page affiche et ce que renvoie /etat.
type Etat struct {
	Logiciel    string `json:"logiciel"`
	Version     string `json:"version"`
	Noeud       string `json:"noeud"` // actif, inactif, absent
	Adresse     string `json:"adresse"`
	Inscription string `json:"inscription"` // absente, quarantaine, admis, refusee
	MiseAJour   string `json:"mise_a_jour"`
	PremierBoot bool   `json:"premier_demarrage_termine"`
	Instant     string `json:"instant"`
}

type registre struct {
	Adresse string `json:"adresse"`
	Etat    string `json:"etat"`
}

type maj struct {
	Version string `json:"version"`
	Jouee   string `json:"jouee"`
}

func lireVersion(code string) string {
	b, err := os.ReadFile(filepath.Join(code, "noeud", "VERSION"))
	if err != nil {
		return "inconnue"
	}
	return strings.TrimSpace(string(b))
}

func lireAdresse(donnees string) string {
	b, err := os.ReadFile(filepath.Join(donnees, "tor", "hs", "hostname"))
	if err != nil {
		return "en préparation"
	}
	return strings.TrimSpace(string(b))
}

func etatService(nom string) string {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return "absent"
	}
	out, err := exec.Command("systemctl", "is-active", nom).Output()
	if err != nil {
		return "inactif"
	}
	switch strings.TrimSpace(string(out)) {
	case "active":
		return "actif"
	case "activating":
		return "démarrage"
	default:
		return "inactif"
	}
}

func lireRegistre(donnees string) (registre, bool) {
	var r registre
	b, err := os.ReadFile(filepath.Join(donnees, "registre.json"))
	if err != nil {
		return r, false
	}
	if json.Unmarshal(b, &r) != nil {
		return r, false
	}
	return r, true
}

func lireMaj(donnees string) string {
	b, err := os.ReadFile(filepath.Join(donnees, "maj-etat.json"))
	if err != nil {
		return "non configurée"
	}
	var m maj
	if json.Unmarshal(b, &m) != nil {
		return "illisible"
	}
	switch {
	case m.Jouee != "":
		return "à jour (" + m.Jouee + ")"
	case m.Version != "":
		return "version " + m.Version + " disponible"
	default:
		return "non configurée"
	}
}

func construire(donnees, code string) Etat {
	e := Etat{
		Logiciel:    "TorDNS",
		Version:     lireVersion(code),
		Noeud:       etatService("tordns.service"),
		Adresse:     lireAdresse(donnees),
		Inscription: "absente",
		MiseAJour:   lireMaj(donnees),
		Instant:     time.Now().UTC().Format(time.RFC3339),
	}
	if _, err := os.Stat(filepath.Join(donnees, "premier-demarrage.ok")); err == nil {
		e.PremierBoot = true
	}
	if r, ok := lireRegistre(donnees); ok {
		switch r.Etat {
		case "admis", "quarantaine", "refusee":
			e.Inscription = r.Etat
		default:
			e.Inscription = "inconnue"
		}
	}
	return e
}

const page = `<!doctype html>
<html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="30">
<title>TorDNS — nœud</title>
<style>
body{font-family:system-ui,sans-serif;max-width:34rem;margin:3rem auto;padding:0 1rem;line-height:1.5}
dt{font-weight:600;margin-top:.8rem}dd{margin:0}
.on{color:#0a7} .off{color:#b00}
</style></head><body>
<h1>Nœud TorDNS</h1>
<p>Cette page ne sort pas du réseau local et n'affiche aucune requête DNS.</p>
<dl>
<dt>Logiciel</dt><dd>{{.Logiciel}} {{.Version}}</dd>
<dt>Nœud</dt><dd class="{{if eq .Noeud "actif"}}on{{else}}off{{end}}">{{.Noeud}}</dd>
<dt>Adresse d'instance</dt><dd>{{.Adresse}}</dd>
<dt>Inscription au registre</dt><dd>{{.Inscription}}</dd>
<dt>Mises à jour</dt><dd>{{.MiseAJour}}</dd>
<dt>Premier démarrage</dt><dd>{{if .PremierBoot}}terminé{{else}}en cours{{end}}</dd>
</dl>
<p><a href="/etat">état en JSON</a></p>
</body></html>`

func main() {
	ecoute := flag.String("ecoute", "0.0.0.0:80", "adresse d'écoute")
	donnees := flag.String("donnees", "/var/lib/tordns", "dossier d'état du nœud")
	code := flag.String("code", "/opt/tordns", "dossier du code du nœud")
	flag.Parse()

	modele := template.Must(template.New("page").Parse(page))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if err := modele.Execute(w, construire(*donnees, *code)); err != nil {
			log.Printf("rendu : %v", err)
		}
	})
	http.HandleFunc("/etat", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(w).Encode(construire(*donnees, *code))
	})

	serveur := &http.Server{
		Addr:              *ecoute,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
	}
	log.Printf("page d'état locale sur %s", *ecoute)
	if err := serveur.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
