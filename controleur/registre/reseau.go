// TorDNS — état public du réseau (Mission 22).
//
// Le registre agrège uniquement ses propres sondes : nombre de nœuds admis et
// joignables, délais des réponses DoH, justesse DNSSEC et publication du
// descripteur. Aucune requête d'utilisateur, aucun nom de domaine demandé,
// aucun contact et aucun compteur de trafic par nœud n'est conservé ici.
//
// Le fichier interne contient les adresses complètes pour recalculer les
// agrégats ; le fichier public (`etat-reseau.json`) ne contient que des
// adresses tronquées et des agrégats.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	categorieCoeur      = "coeur"
	categorieCommunaute = "communaute"

	fenetreSondes      = 24 * time.Hour
	historiqueMax      = 30 * 24 * time.Hour
	maxEchantillons    = 50000
	troncatureAdresse  = 8
	versionEtatReseau  = 1
	fenetreHistoriqueH = 30 * 24
)

type echantillon struct {
	Temps     time.Time `json:"temps"`
	Categorie string    `json:"categorie"`
	Adresse   string    `json:"adresse"`
	DelaiMs   float64   `json:"delai_ms"`
	Correct   bool      `json:"correct"`
	Joignable bool      `json:"joignable"`
}

type agregatCategorie struct {
	Sondes      int     `json:"sondes"`
	Correctes   int     `json:"correctes"`
	DelaiMedian float64 `json:"delai_median_ms"`
	DelaiP95    float64 `json:"delai_p95_ms"`
	TauxDNSSEC  float64 `json:"taux_dnssec_correct"`
}

type agregatHoraire struct {
	Heure      time.Time        `json:"heure"`
	Coeur      agregatCategorie `json:"coeur"`
	Communaute agregatCategorie `json:"communaute"`
}

type noeudReseau struct {
	Adresse   string `json:"adresse"`
	Joignable bool   `json:"joignable"`
}

type categorieReseau struct {
	Nom              string        `json:"nom"`
	NoeudsAdmis      int           `json:"noeuds_admis"`
	NoeudsJoignables int           `json:"noeuds_joignables"`
	DelaiMedianMs    float64       `json:"delai_median_ms"`
	DelaiP95Ms       float64       `json:"delai_p95_ms"`
	TauxDNSSEC       float64       `json:"taux_dnssec_correct"`
	Noeuds           []noeudReseau `json:"noeuds"`
}

type etatReseauPublic struct {
	Version                        int               `json:"version"`
	Genere                         time.Time         `json:"genere"`
	FenetreHeures                  int               `json:"fenetre_heures"`
	HistoriqueHeures               int               `json:"historique_heures"`
	Adresses                       []categorieReseau `json:"adresses"`
	DernierePublicationDescripteur *time.Time        `json:"derniere_publication_descripteur,omitempty"`
	Historique                     []agregatHoraire  `json:"historique"`
}

type etatReseauInterne struct {
	Echantillons []echantillon    `json:"echantillons"`
	Historique   []agregatHoraire `json:"historique"`
	Derniers     map[string]bool  `json:"derniers"`
	Descripteur  time.Time        `json:"descripteur,omitempty"`
}

type reseau struct {
	mu     sync.Mutex
	chemin string
	etat   etatReseauInterne
}

func chargerReseau(chemin string) (*reseau, error) {
	r := &reseau{chemin: chemin, etat: etatReseauInterne{
		Derniers: map[string]bool{},
	}}
	if chemin == "" {
		return r, nil
	}
	brut, err := os.ReadFile(chemin)
	if errors.Is(err, os.ErrNotExist) {
		return r, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(brut, &r.etat); err != nil {
		return nil, fmt.Errorf("état réseau illisible : %w", err)
	}
	if r.etat.Derniers == nil {
		r.etat.Derniers = map[string]bool{}
	}
	return r, nil
}

func cleDernier(categorie, adresse string) string {
	return categorie + "\x00" + adresse
}

func (r *reseau) ajouterSonde(categorie, adresse string, mesures []mesureSonde, joignable bool, maintenant time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, mesure := range mesures {
		r.etat.Echantillons = append(r.etat.Echantillons, echantillon{
			Temps:     maintenant.UTC(),
			Categorie: categorie,
			Adresse:   adresse,
			DelaiMs:   float64(mesure.Delai.Microseconds()) / 1000,
			Correct:   mesure.Correct,
			Joignable: mesure.Joignable,
		})
	}
	r.etat.Derniers[cleDernier(categorie, adresse)] = joignable
	r.purger(maintenant)
}

func (r *reseau) purger(maintenant time.Time) {
	limite := maintenant.Add(-fenetreSondes)
	gardes := r.etat.Echantillons[:0]
	for _, e := range r.etat.Echantillons {
		if e.Temps.After(limite) {
			gardes = append(gardes, e)
		}
	}
	r.etat.Echantillons = gardes
	// Plafond de sécurité : si un déploiement dépasse largement la charge
	// prévue, on conserve un échantillon sur deux plutôt que de laisser le
	// fichier grossir sans limite. Les percentiles restent représentatifs.
	if len(r.etat.Echantillons) > maxEchantillons {
		reduits := make([]echantillon, 0, len(r.etat.Echantillons)/2+1)
		for i := 0; i < len(r.etat.Echantillons); i += 2 {
			reduits = append(reduits, r.etat.Echantillons[i])
		}
		r.etat.Echantillons = reduits
	}
	r.rafraichirHistorique(maintenant)
}

func (r *reseau) rafraichirHistorique(maintenant time.Time) {
	limite := maintenant.Add(-historiqueMax)
	parHeure := map[time.Time]*agregatHoraire{}
	for _, h := range r.etat.Historique {
		if !h.Heure.Before(limite) {
			copie := h
			parHeure[h.Heure.UTC().Truncate(time.Hour)] = &copie
		}
	}
	type cleHeure struct {
		heure time.Time
		cat   string
	}
	mesures := map[cleHeure][]float64{}
	correctes := map[cleHeure]int{}
	totaux := map[cleHeure]int{}
	for _, e := range r.etat.Echantillons {
		heure := e.Temps.UTC().Truncate(time.Hour)
		k := cleHeure{heure, e.Categorie}
		totaux[k]++
		if e.Correct {
			correctes[k]++
		}
		if e.Joignable {
			mesures[k] = append(mesures[k], e.DelaiMs)
		}
	}
	for k := range totaux {
		valeurs := mesures[k]
		h := parHeure[k.heure]
		if h == nil {
			h = &agregatHoraire{Heure: k.heure}
			parHeure[k.heure] = h
		}
		ag := agregatCategorie{
			Sondes:      totaux[k],
			Correctes:   correctes[k],
			DelaiMedian: arrondi(centile(valeurs, 0.5)),
			DelaiP95:    arrondi(centile(valeurs, 0.95)),
		}
		if ag.Sondes > 0 {
			ag.TauxDNSSEC = arrondi(float64(ag.Correctes) / float64(ag.Sondes))
		}
		switch k.cat {
		case categorieCoeur:
			h.Coeur = ag
		case categorieCommunaute:
			h.Communaute = ag
		}
	}
	heures := make([]time.Time, 0, len(parHeure))
	for h := range parHeure {
		if !h.Before(limite) {
			heures = append(heures, h)
		}
	}
	sort.Slice(heures, func(i, j int) bool { return heures[i].Before(heures[j]) })
	if len(heures) > fenetreHistoriqueH {
		heures = heures[len(heures)-fenetreHistoriqueH:]
	}
	historique := make([]agregatHoraire, 0, len(heures))
	for _, h := range heures {
		historique = append(historique, *parHeure[h])
	}
	r.etat.Historique = historique
}

func (r *reseau) dernier(categorie, adresse string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.etat.Derniers[cleDernier(categorie, adresse)]
}

func (r *reseau) fixerDescripteur(t time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if t.After(r.etat.Descripteur) {
		r.etat.Descripteur = t.UTC()
	}
}

func (r *reseau) instantane(maintenant time.Time) (etatReseauPublic, error) {
	r.mu.Lock()
	resume := r.resumeLocked(maintenant)
	historique := append([]agregatHoraire(nil), r.etat.Historique...)
	descripteur := r.etat.Descripteur
	r.mu.Unlock()

	adresses := make([]categorieReseau, 0, 2)
	for _, cat := range []string{categorieCoeur, categorieCommunaute} {
		ag := resume[cat]
		adresses = append(adresses, categorieReseau{
			Nom:           cat,
			DelaiMedianMs: ag.DelaiMedian,
			DelaiP95Ms:    ag.DelaiP95,
			TauxDNSSEC:    ag.TauxDNSSEC,
			Noeuds:        []noeudReseau{},
		})
	}
	e := etatReseauPublic{
		Version:          versionEtatReseau,
		Genere:           maintenant.UTC(),
		FenetreHeures:    24,
		HistoriqueHeures: fenetreHistoriqueH,
		Adresses:         adresses,
		Historique:       historique,
	}
	if !descripteur.IsZero() {
		t := descripteur.UTC()
		e.DernierePublicationDescripteur = &t
	}
	return e, nil
}

func (r *reseau) resumeLocked(maintenant time.Time) map[string]agregatCategorie {
	limite := maintenant.Add(-fenetreSondes)
	valeurs := map[string][]float64{}
	correctes := map[string]int{}
	totaux := map[string]int{}
	for _, e := range r.etat.Echantillons {
		if e.Temps.Before(limite) {
			continue
		}
		totaux[e.Categorie]++
		if e.Correct {
			correctes[e.Categorie]++
		}
		if e.Joignable {
			valeurs[e.Categorie] = append(valeurs[e.Categorie], e.DelaiMs)
		}
	}
	resultat := map[string]agregatCategorie{}
	for _, cat := range []string{categorieCoeur, categorieCommunaute} {
		ag := agregatCategorie{
			Sondes:      totaux[cat],
			Correctes:   correctes[cat],
			DelaiMedian: arrondi(centile(valeurs[cat], 0.5)),
			DelaiP95:    arrondi(centile(valeurs[cat], 0.95)),
		}
		if ag.Sondes > 0 {
			ag.TauxDNSSEC = arrondi(float64(ag.Correctes) / float64(ag.Sondes))
		}
		resultat[cat] = ag
	}
	return resultat
}

func (r *reseau) enregistrerInterne() error {
	if r.chemin == "" {
		return nil
	}
	r.mu.Lock()
	brut, err := json.MarshalIndent(r.etat, "", "  ")
	r.mu.Unlock()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(r.chemin), 0o700); err != nil {
		return err
	}
	tmp := r.chemin + ".tmp"
	if err := os.WriteFile(tmp, append(brut, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, r.chemin)
}

// statutOnionbalance ne reprend que les dates de tentative de publication.
// Aucune adresse d'instance ni clé n'est conservée : le reste du JSON est
// ignoré volontairement.
type statutOnionbalance struct {
	Services []struct {
		PublishAttemptFirstDescriptor  *string `json:"publishAttemptFirstDescriptor"`
		PublishAttemptSecondDescriptor *string `json:"publishAttemptSecondDescriptor"`
	} `json:"services"`
}

func datePublicationOnionbalance(chemin string) (time.Time, bool) {
	conn, err := net.DialTimeout("unix", chemin, time.Second)
	if err != nil {
		return time.Time{}, false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	brut, err := io.ReadAll(io.LimitReader(conn, 64*1024))
	if err != nil {
		return time.Time{}, false
	}
	var statut statutOnionbalance
	if err := json.Unmarshal(brut, &statut); err != nil {
		return time.Time{}, false
	}
	var derniere time.Time
	for _, service := range statut.Services {
		for _, valeur := range []*string{service.PublishAttemptFirstDescriptor, service.PublishAttemptSecondDescriptor} {
			if valeur == nil || *valeur == "" {
				continue
			}
			t, err := time.ParseInLocation("2006-01-02 15:04:05", *valeur, time.UTC)
			if err == nil && t.After(derniere) {
				derniere = t
			}
		}
	}
	return derniere, !derniere.IsZero()
}

func (r *registre) majDescripteur() {
	if r.cfg.OnionbalanceStatus != "" {
		if t, ok := datePublicationOnionbalance(r.cfg.OnionbalanceStatus); ok {
			r.reseau.fixerDescripteur(t)
			return
		}
	}
	if r.cfg.DescripteurFichier == "" {
		return
	}
	info, err := os.Stat(r.cfg.DescripteurFichier)
	if err == nil {
		r.reseau.fixerDescripteur(info.ModTime())
	}
}

// instantaneReseau combine les agrégats (sans adresses) et les nœuds connus
// du registre. Les adresses sont tronquées dans la structure publique.
func (r *registre) instantaneReseau(maintenant time.Time) etatReseauPublic {
	base, _ := r.reseau.instantane(maintenant)
	r.mu.Lock()
	admis := make([]string, 0, len(r.etat.Admis))
	for a := range r.etat.Admis {
		admis = append(admis, a)
	}
	coeur := append([]string(nil), r.coeur...)
	r.mu.Unlock()
	sort.Strings(admis)
	for i := range base.Adresses {
		var adresses []string
		switch base.Adresses[i].Nom {
		case categorieCoeur:
			adresses = coeur
		case categorieCommunaute:
			adresses = admis
		}
		noeuds := make([]noeudReseau, 0, len(adresses))
		joignables := 0
		for _, a := range adresses {
			j := r.reseau.dernier(base.Adresses[i].Nom, a)
			if j {
				joignables++
			}
			noeuds = append(noeuds, noeudReseau{Adresse: tronquerAdresse(a), Joignable: j})
		}
		base.Adresses[i].NoeudsAdmis = len(noeuds)
		base.Adresses[i].NoeudsJoignables = joignables
		base.Adresses[i].Noeuds = noeuds
	}
	return base
}

func (r *registre) publierReseau(maintenant time.Time) error {
	r.majDescripteur()
	e := r.instantaneReseau(maintenant)
	if err := r.reseau.enregistrerInterne(); err != nil {
		return err
	}
	return ecrireEtatReseau(r.cfg.ReseauFichier, e)
}

func ecrireEtatReseau(chemin string, e etatReseauPublic) error {
	if chemin == "" {
		return nil
	}
	brut, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(chemin), 0o700); err != nil {
		return err
	}
	tmp := chemin + ".tmp"
	if err := os.WriteFile(tmp, append(brut, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, chemin)
}

func arrondi(v float64) float64 {
	return math.Round(v*10) / 10
}

// centile utilise le rang le plus proche (p95 = 95e valeur sur 100). Il ne
// conserve pas les noms de domaine : seuls les délais sont triés.
func centile(valeurs []float64, p float64) float64 {
	if len(valeurs) == 0 {
		return 0
	}
	triees := append([]float64(nil), valeurs...)
	sort.Float64s(triees)
	rang := int(math.Ceil(p*float64(len(triees)))) - 1
	if rang < 0 {
		rang = 0
	}
	if rang >= len(triees) {
		rang = len(triees) - 1
	}
	return triees[rang]
}

func tronquerAdresse(adresse string) string {
	if len(adresse) <= troncatureAdresse {
		return adresse
	}
	return adresse[:troncatureAdresse] + "…"
}

func nomCategorie(cat string) string {
	switch cat {
	case categorieCoeur:
		return "Cœur"
	case categorieCommunaute:
		return "Communauté"
	default:
		return cat
	}
}

func pourcent(v float64) string {
	return fmt.Sprintf("%.1f %%", v*100)
}

func millisecondes(v float64) string {
	return fmt.Sprintf("%.1f ms", v)
}

var pageReseauModele = template.Must(template.New("reseau").Funcs(template.FuncMap{
	"nom":      nomCategorie,
	"pourcent": pourcent,
	"ms":       millisecondes,
}).Parse(`<!doctype html>
<html lang="fr">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>TorDNS — état du réseau</title>
<style>body{font-family:system-ui,sans-serif;max-width:58rem;margin:2rem auto;padding:0 1rem;line-height:1.5;color:#17212b;background:#fff}table{border-collapse:collapse;width:100%;margin:1rem 0}td,th{padding:.35rem .5rem;border-bottom:1px solid #ccd;text-align:left;font-size:.9rem}code{font-size:.85rem}.cartes{display:flex;gap:1rem;flex-wrap:wrap}.carte{border:1px solid #ccd;border-radius:.4rem;padding:.8rem 1rem;min-width:14rem}.carte h2{font-size:1rem;margin:0 0 .4rem}.chiffre{font-size:1.5rem;font-weight:600}.note{background:#f4f6f8;border-left:4px solid #667;padding:.6rem .8rem}svg{max-width:100%;height:auto;border:1px solid #dde;background:#fbfbfd}.legende{font-size:.85rem;color:#445}</style>
</head>
<body>
<h1>TorDNS — état du réseau</h1>
<p>Cette page ne montre que des agrégats de sondes du contrôleur. Elle ne contient
aucune requête d'utilisateur, aucun nom de domaine demandé, aucun contact et
aucun compteur de trafic par nœud.</p>
<p class="note">Les nœuds bénévoles sont affichés sous leurs huit premiers
caractères seulement. Un bénévole peut journaliser les requêtes qu'il reçoit :
la validation DNSSEC limite le mensonge sur les zones signées, pas la collecte.</p>
<div class="cartes">
{{range .Adresses}}<section class="carte">
<h2>{{nom .Nom}}</h2>
<p class="chiffre">{{.NoeudsJoignables}} / {{.NoeudsAdmis}}</p>
<p>nœuds joignables / admis</p>
{{if .Noeuds}}<p>Délai médian : {{ms .DelaiMedianMs}}<br>p95 : {{ms .DelaiP95Ms}}<br>DNSSEC correct : {{pourcent .TauxDNSSEC}}</p>
<table><tr><th>Instance</th><th>Joignable</th></tr>
{{range .Noeuds}}<tr><td><code>{{.Adresse}}</code></td><td>{{if .Joignable}}oui{{else}}non{{end}}</td></tr>{{end}}
</table>{{else}}<p>Aucune sonde sur 24 h.</p>{{end}}
</section>{{end}}
</div>
<p>Dernière publication du descripteur :
{{if .DernierePublicationDescripteur}}<time datetime="{{.DernierePublicationDescripteur.Format "2006-01-02T15:04:05Z07:00"}}">{{.DernierePublicationDescripteur.Format "2006-01-02 15:04 UTC"}}</time>{{else}}non connue{{end}}.</p>
<h2>Délais sur les 30 derniers jours</h2>
{{.Graphique}}
<p class="legende">Chaque point est un agrégat horaire. Les heures sans sonde
ne sont pas dessinées. Le JSON correspondant est disponible sur
<code>/reseau.json</code>.</p>
<p><a href="/">Retour aux nœuds communauté</a></p>
</body></html>
`))

// graphiqueSVG dessine les médianes horaires cœur et communauté sans
// JavaScript. Les valeurs sont numériques et les libellés sont fixes.
func graphiqueSVG(historique []agregatHoraire) template.HTML {
	const largeur, hauteur = 720, 220
	const margeG, margeD, margeH, margeB = 42, 12, 18, 30
	if len(historique) == 0 {
		return template.HTML(`<p>Aucun historique pour le moment.</p>`)
	}
	max := 1.0
	for _, h := range historique {
		for _, v := range []float64{h.Coeur.DelaiMedian, h.Communaute.DelaiMedian} {
			if v > max {
				max = v
			}
		}
	}
	largeurUtile := float64(largeur - margeG - margeD)
	hauteurUtile := float64(hauteur - margeH - margeB)
	x := func(i int) float64 {
		if len(historique) == 1 {
			return float64(margeG) + largeurUtile/2
		}
		return float64(margeG) + float64(i)*largeurUtile/float64(len(historique)-1)
	}
	y := func(v float64) float64 {
		return float64(margeH) + hauteurUtile*(1-v/max)
	}
	var b strings.Builder
	fmt.Fprintf(&b, `<svg viewBox="0 0 %d %d" role="img" aria-labelledby="graph-titre graph-desc" xmlns="http://www.w3.org/2000/svg">`, largeur, hauteur)
	b.WriteString(`<title id="graph-titre">Délai médian des sondes par heure</title>`)
	b.WriteString(`<desc id="graph-desc">Deux courbes : nœuds cœur et nœuds communauté. L’axe vertical est en millisecondes.</desc>`)
	for i := 0; i <= 4; i++ {
		v := max * float64(i) / 4
		yv := y(v)
		fmt.Fprintf(&b, `<line x1="%d" y1="%.1f" x2="%d" y2="%.1f" stroke="#dde" stroke-width="1"/>`, margeG, yv, largeur-margeD, yv)
		fmt.Fprintf(&b, `<text x="%d" y="%.1f" font-size="10" text-anchor="end" fill="#445">%.0f ms</text>`, margeG-5, yv+3, v)
	}
	for _, serie := range []struct {
		nom     string
		couleur string
		valeurs func(agregatHoraire) float64
	}{
		{"cœur", "#0b7285", func(h agregatHoraire) float64 { return h.Coeur.DelaiMedian }},
		{"communauté", "#c2255c", func(h agregatHoraire) float64 { return h.Communaute.DelaiMedian }},
	} {
		var points []string
		for i, h := range historique {
			if serie.valeurs(h) <= 0 {
				continue
			}
			points = append(points, fmt.Sprintf("%.1f,%.1f", x(i), y(serie.valeurs(h))))
		}
		if len(points) > 0 {
			fmt.Fprintf(&b, `<polyline fill="none" stroke="%s" stroke-width="2" points="%s"/>`, serie.couleur, strings.Join(points, " "))
		}
	}
	b.WriteString(`</svg>`)
	b.WriteString(`<p class="legende"><span style="color:#0b7285">■</span> cœur &nbsp; <span style="color:#c2255c">■</span> communauté</p>`)
	return template.HTML(b.String())
}
