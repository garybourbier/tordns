// TorDNS — surface HTTP du registre (Mission 10).
//
// Exposé uniquement par le service caché dédié du contrôleur. Aucune requête
// n'est journalisée : ni adresse source, ni nom de domaine, ni contact.
package main

import (
	"encoding/json"
	"html/template"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

type reponseInscription struct {
	Etat                string `json:"etat"`
	Adresse             string `json:"adresse"`
	Defi                string `json:"defi"`
	QuarantaineSecondes int64  `json:"quarantaine_secondes"`
	Page                string `json:"page"`
	Message             string `json:"message"`
}

type cleContexte int

// cleCircuit porte l'identifiant de circuit Tor lu dans le PROXY v2.
const cleCircuit cleContexte = 1

// sourceInscription renvoie la clé de limitation : le circuit Tor quand le
// PROXY v2 le fournit, sinon l'adresse réseau (tests, healthcheck local).
func sourceInscription(r *http.Request) string {
	if circuit, ok := r.Context().Value(cleCircuit).(string); ok && circuit != "" {
		return "circuit:" + circuit
	}
	hote, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return hote
}

func lireJSON(r *http.Request, cible any) error {
	defer r.Body.Close()
	brut, err := io.ReadAll(io.LimitReader(r.Body, 8192))
	if err != nil {
		return err
	}
	return json.Unmarshal(brut, cible)
}

func ecrireJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (r *registre) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/inscription", r.posterInscription)
	mux.HandleFunc("/inscription/confirmer", r.posterConfirmation)
	mux.HandleFunc("/etat", r.getEtat)
	mux.HandleFunc("/", r.getPage)
	return mux
}

func (r *registre) posterInscription(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		ecrireJSON(w, http.StatusMethodNotAllowed, map[string]string{"erreur": "méthode non autorisée"})
		return
	}
	var corps struct {
		Adresse string `json:"adresse_instance"`
		Contact string `json:"contact_facultatif"`
	}
	if err := lireJSON(req, &corps); err != nil {
		ecrireJSON(w, http.StatusBadRequest, map[string]string{"erreur": "corps JSON invalide"})
		return
	}
	c, err := r.inscrire(corps.Adresse, corps.Contact, sourceInscription(req))
	if err != nil {
		code := http.StatusUnprocessableEntity
		if strings.Contains(err.Error(), "quota") || strings.Contains(err.Error(), "trop") {
			code = http.StatusTooManyRequests
		}
		ecrireJSON(w, code, map[string]string{"erreur": err.Error()})
		return
	}
	ecrireJSON(w, http.StatusCreated, reponseInscription{
		Etat:                "candidat",
		Adresse:             c.Adresse,
		Defi:                c.Defi,
		QuarantaineSecondes: int64(r.cfg.Quarantaine.Seconds()),
		Page:                "http://" + req.Host + "/",
		Message:             "écrivez ce défi dans <données>/tor/defi, puis appelez /inscription/confirmer",
	})
}

func (r *registre) posterConfirmation(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		ecrireJSON(w, http.StatusMethodNotAllowed, map[string]string{"erreur": "méthode non autorisée"})
		return
	}
	var corps struct {
		Adresse string `json:"adresse_instance"`
	}
	if err := lireJSON(req, &corps); err != nil {
		ecrireJSON(w, http.StatusBadRequest, map[string]string{"erreur": "corps JSON invalide"})
		return
	}
	c, err := r.confirmer(corps.Adresse)
	if err != nil {
		ecrireJSON(w, http.StatusUnprocessableEntity, map[string]string{"erreur": err.Error()})
		return
	}
	ecrireJSON(w, http.StatusOK, reponseInscription{
		Etat:                "confirme",
		Adresse:             c.Adresse,
		QuarantaineSecondes: int64(r.cfg.Quarantaine.Seconds()),
		Page:                "http://" + req.Host + "/",
		Message:             "défi vérifié ; le nœud est sondé pendant la quarantaine",
	})
}

func (r *registre) getEtat(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		ecrireJSON(w, http.StatusMethodNotAllowed, map[string]string{"erreur": "méthode non autorisée"})
		return
	}
	ecrireJSON(w, http.StatusOK, r.instantane())
}

var pageModele = template.Must(template.New("page").Parse(`<!doctype html>
<html lang="fr">
<head><meta charset="utf-8"><title>TorDNS — nœuds communauté</title>
<style>body{font-family:system-ui,sans-serif;max-width:46rem;margin:2rem auto;padding:0 1rem;line-height:1.5}table{border-collapse:collapse;width:100%}td,th{padding:.3rem .5rem;border-bottom:1px solid #ccc;text-align:left;font-size:.9rem}code{font-size:.85rem}</style>
</head>
<body>
<h1>TorDNS — nœuds communauté</h1>
<p>Ces nœuds bénévoles ont servi un défi et passé la quarantaine de sondes
DNSSEC. Ils servent l'adresse <strong>communauté</strong>, jamais l'adresse
cœur.</p>
<p><strong>Un bénévole peut journaliser ses requêtes.</strong> Rien ici ne
permet de prouver le contraire : la validation DNSSEC côté client limite le
mensonge sur les zones signées, pas la collecte.</p>
{{if .Admis}}<table>
<tr><th>Adresse d'instance</th><th>Admis depuis</th><th>Disponibilité</th></tr>
{{range .Admis}}<tr><td><code>{{.Adresse}}</code></td><td>{{.Age}}</td><td>{{.Dispo}}</td></tr>{{end}}
</table>{{else}}<p>Aucun nœud admis pour le moment.</p>{{end}}
<p>Inscription : <code>installer.sh --rejoindre &lt;adresse-du-registre&gt;</code>.</p>
<p>Quarantaine : {{.Quarantaine}}.</p>
</body></html>
`))

func (r *registre) getPage(w http.ResponseWriter, req *http.Request) {
	if req.URL.Path != "/" {
		http.NotFound(w, req)
		return
	}
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}
	e := r.instantane()
	type ligne struct{ Adresse, Age, Dispo string }
	lignes := make([]ligne, 0, len(e.Admis))
	maintenant := r.cfg.Maintenant()
	for _, a := range e.Admis {
		lignes = append(lignes, ligne{
			Adresse: a.Adresse,
			Age:     dureeCourte(maintenant.Sub(a.Depuis)),
			Dispo:   strconv.Itoa(int(a.Disponible*100+0.5)) + " %",
		})
	}
	sort.Slice(lignes, func(i, j int) bool { return lignes[i].Adresse < lignes[j].Adresse })
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = pageModele.Execute(w, struct {
		Admis       []ligne
		Quarantaine string
	}{lignes, dureeCourte(r.cfg.Quarantaine)})
}

func dureeCourte(d time.Duration) string {
	if d < time.Hour {
		return strconv.Itoa(int(d.Minutes()+0.5)) + " min"
	}
	if d < 48*time.Hour {
		return strconv.Itoa(int(d.Hours()+0.5)) + " h"
	}
	return strconv.Itoa(int(d.Hours()/24+0.5)) + " j"
}
