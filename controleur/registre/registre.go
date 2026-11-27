// TorDNS — registre et admission des nœuds bénévoles (Mission 10).
//
// Un nœud s'inscrit, sert un défi aléatoire sur son service caché, puis est
// sondé (justesse DNSSEC, disponibilité) pendant une quarantaine avant
// d'entrer dans le pool communauté. Le pool cœur n'est jamais touché ici.
//
// Aucun nom de domaine testé n'est écrit dans un journal : les erreurs ne
// portent que sur le nœud et le type d'échec.
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	mathrand "math/rand"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	errDefiAbsent   = errors.New("défi non servi par le nœud")
	errMensonge     = errors.New("réponse DNSSEC ou justesse incorrecte")
	errIndisponible = errors.New("nœud indisponible")
	reAdresse       = regexp.MustCompile(`^([a-z2-7]{56}\.onion|[a-zA-Z0-9.-]+:[0-9]{1,5})$`)
	// UNE SEULE GRAMMAIRE pour une adresse d'instance : un service caché v3. L'ancienne
	// grammaire acceptait aussi « hôte:port », d'où deux écritures d'une même cible
	// (contournement de la liste des évincés) et un contrôleur qui allait chercher
	// n'importe quelle adresse nommée par l'appelant (relecture du 24/11, point 5b-c).
	reOnion = regexp.MustCompile(`^[a-z2-7]{56}\.onion$`)
	// Les bancs de test seulement (config.AdressesLocales) : la boucle locale.
	reLocale = regexp.MustCompile(`^(127\.0\.0\.1|localhost):([0-9]{1,5})$`)
)

type config struct {
	// AdressesLocales accepte « 127.0.0.1:port » en plus des .onion : bancs de
	// test uniquement, jamais en service.
	AdressesLocales      bool
	Quarantaine          time.Duration
	EchecsMax            int
	DoutesMax            int
	IndispoMax           int
	SondesMin            int
	MaxInscriptionsJour  int
	MaxParIP             int
	Reference            string
	Domaines             []string
	DomainesParPasse     int
	Client               *http.Client
	Maintenant           func() time.Time
	Hook                 func()
	CoeurFichier         string
	DescripteurFichier   string
	OnionbalanceStatus   string
	ReseauFichier        string
	ReseauInterneFichier string
	// Mission 28 : rétention des données
	RetentionCandidats time.Duration // durée max d'un candidat non confirmé
	RetentionEvinces   time.Duration // durée max d'une éviction conservée
}

type candidat struct {
	Adresse   string               `json:"adresse"`
	Defi      string               `json:"defi"`
	Contact   string               `json:"contact,omitempty"`
	Depuis    time.Time            `json:"depuis"`
	Confirme  bool                 `json:"confirme"`
	SondesOK  int                  `json:"sondes_ok"`
	SondesKO  int                  `json:"sondes_ko"`
	DernierOK time.Time            `json:"dernier_ok,omitempty"` // Pour remettre les indisponibilités consécutives à zéro
	DernierKO time.Time            `json:"dernier_ko,omitempty"`
	Doutes    map[string]time.Time `json:"doutes,omitempty"`
	// Mission 28 : quota journalier décrémenté à la confirmation, pas à l'inscription
	QuotaPris bool `json:"quota_pris,omitempty"`
}

type admis struct {
	Adresse    string               `json:"adresse"`
	Depuis     time.Time            `json:"depuis"`
	SondesOK   int                  `json:"sondes_ok"`
	SondesKO   int                  `json:"sondes_ko"`
	Disponible float64              `json:"disponibilite"`
	DernierOK  time.Time            `json:"dernier_ok"`
	Doutes     map[string]time.Time `json:"doutes,omitempty"`
}

type etat struct {
	Candidats    map[string]*candidat `json:"candidats"`
	Admis        map[string]*admis    `json:"admis"`
	Evinces      map[string]time.Time `json:"evinces"`
	Inscriptions map[string]int       `json:"inscriptions_ip"`
	Jour         string               `json:"jour"`
	TotalJour    int                  `json:"total_jour"`
}

type registre struct {
	mu         sync.Mutex
	cfg        config
	etat       etat
	chemin     string
	cheminPool string
	reseau     *reseau
	coeur      []string
}

type mesureSonde struct {
	Delai     time.Duration
	Correct   bool
	Joignable bool
	// Mission 28 : identifiant DNS aléatoire pour la sonde
	DnsID uint16 `json:"dns_id,omitempty"`
}

func nouveauRegistre(chemin, cheminPool string, cfg config) (*registre, error) {
	if cfg.Maintenant == nil {
		cfg.Maintenant = time.Now
	}
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 15 * time.Second}
	}
	if cfg.Quarantaine <= 0 {
		cfg.Quarantaine = 72 * time.Hour
	}
	if cfg.EchecsMax <= 0 {
		cfg.EchecsMax = 1
	}
	if cfg.DoutesMax <= 0 {
		cfg.DoutesMax = 3
	}
	if cfg.IndispoMax <= 0 {
		cfg.IndispoMax = 6
	}
	if cfg.SondesMin <= 0 {
		cfg.SondesMin = 2
	}
	if cfg.MaxInscriptionsJour <= 0 {
		cfg.MaxInscriptionsJour = 50
	}
	if cfg.MaxParIP <= 0 {
		cfg.MaxParIP = 3
	}
	if cfg.DomainesParPasse <= 0 {
		cfg.DomainesParPasse = 3
	}
	if len(cfg.Domaines) == 0 {
		cfg.Domaines = []string{
			"ietf.org", "nlnetlabs.nl", "internetsociety.org", "dnssec-failed.org",
		}
	}
	reseauEtat, err := chargerReseau(cfg.ReseauInterneFichier)
	if err != nil {
		return nil, err
	}
	r := &registre{cfg: cfg, chemin: chemin, cheminPool: cheminPool, reseau: reseauEtat, etat: etat{
		Candidats:    map[string]*candidat{},
		Admis:        map[string]*admis{},
		Evinces:      map[string]time.Time{},
		Inscriptions: map[string]int{},
	}}
	if chemin != "" {
		brut, err := os.ReadFile(chemin)
		if err == nil {
			if err := json.Unmarshal(brut, &r.etat); err != nil {
				return nil, fmt.Errorf("état du registre illisible : %w", err)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	// Un state ancien peut ne pas avoir toutes les cartes.
	if r.etat.Candidats == nil {
		r.etat.Candidats = map[string]*candidat{}
	}
	if r.etat.Admis == nil {
		r.etat.Admis = map[string]*admis{}
	}
	if r.etat.Evinces == nil {
		r.etat.Evinces = map[string]time.Time{}
	}
	if r.etat.Inscriptions == nil {
		r.etat.Inscriptions = map[string]int{}
	}
	r.coeur = r.lireCoeur()
	return r, nil
}

func (r *registre) enregistrer() error {
	if r.chemin == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(r.chemin), 0o700); err != nil {
		return err
	}
	brut, err := json.MarshalIndent(r.etat, "", "  ")
	if err != nil {
		return err
	}
	tmp := r.chemin + ".tmp"
	if err := os.WriteFile(tmp, append(brut, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, r.chemin)
}

// changerJour remet à zéro les compteurs journaliers.
func (r *registre) changerJour(maintenant time.Time) {
	jour := maintenant.UTC().Format("2006-01-02")
	if r.etat.Jour != jour {
		r.etat.Jour = jour
		r.etat.TotalJour = 0
		r.etat.Inscriptions = map[string]int{}
	}
	// Mission 28 : purge des candidats et évincés anciens
	if r.cfg.RetentionCandidats > 0 {
		limite := maintenant.Add(-r.cfg.RetentionCandidats)
		for adresse, c := range r.etat.Candidats {
			if !c.Confirme && c.Depuis.Before(limite) {
				delete(r.etat.Candidats, adresse)
			}
		}
	}
	if r.cfg.RetentionEvinces > 0 {
		limite := maintenant.Add(-r.cfg.RetentionEvinces)
		for adresse, date := range r.etat.Evinces {
			if date.Before(limite) {
				delete(r.etat.Evinces, adresse)
			}
		}
	}
}

func defiAleatoire() (string, error) {
	brut := make([]byte, 32)
	if _, err := rand.Read(brut); err != nil {
		return "", err
	}
	return hex.EncodeToString(brut), nil
}

// verifierDefi lit le défi servi par le nœud, avec un plafond de taille.
func (r *registre) verifierDefi(adresse, defi string) error {
	url := "http://" + adresse + "/.well-known/tordns/defi"
	reponse, err := r.cfg.Client.Get(url)
	if err != nil {
		return fmt.Errorf("%w : %v", errDefiAbsent, err)
	}
	defer reponse.Body.Close()
	if reponse.StatusCode != http.StatusOK {
		return errDefiAbsent
	}
	corps, err := io.ReadAll(io.LimitReader(reponse.Body, 256))
	if err != nil {
		return errDefiAbsent
	}
	if strings.TrimSpace(string(corps)) != defi {
		return errDefiAbsent
	}
	return nil
}

// inscrire crée un candidat et lui remet un défi ; la preuve du défi se fait
// dans confirmer. ip sert uniquement aux limites d'inscription ; elle n'est
// jamais conservée.
// Mission 28 : le quota journalier se décompte à la confirmation, pas à l'inscription.
func (r *registre) inscrire(adresse, contact, ip string) (candidat, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	adresse, ok := r.normaliser(adresse)
	if !ok {
		return candidat{}, errors.New("adresse d'instance invalide")
	}
	maintenant := r.cfg.Maintenant()
	r.changerJour(maintenant)
	if _, ok := r.etat.Evinces[adresse]; ok {
		return candidat{}, errors.New("adresse évincée : inscription refusée")
	}
	if _, ok := r.etat.Admis[adresse]; ok {
		return candidat{}, errors.New("adresse déjà admise")
	}
	// Mission 28 : quota vérifié à la confirmation, pas ici. On garde juste
	// la limite par IP pour l'inscription immédiate.
	if r.etat.Inscriptions[ip] >= r.cfg.MaxParIP {
		return candidat{}, errors.New("trop d'inscriptions depuis cette source aujourd'hui")
	}
	// Une nouvelle demande remplace le défi précédent : le nœud doit prouver
	// à nouveau qu'il contrôle l'adresse.
	delete(r.etat.Candidats, adresse)
	defi, err := defiAleatoire()
	if err != nil {
		return candidat{}, err
	}
	c := &candidat{
		Adresse:   adresse,
		Defi:      defi,
		Contact:   strings.TrimSpace(contact),
		Depuis:    maintenant,
		QuotaPris: false,
	}
	r.etat.Candidats[adresse] = c
	r.etat.Inscriptions[ip]++
	if err := r.enregistrer(); err != nil {
		return candidat{}, err
	}
	return *c, nil
}

// confirmer vérifie que le nœud sert maintenant le défi qui lui a été remis.
// Mission 28 : le quota journalier se décompte à la confirmation.
func (r *registre) confirmer(adresse string) (candidat, error) {
	adresse, valide := r.normaliser(adresse)
	if !valide {
		return candidat{}, errors.New("inscription inconnue")
	}
	r.mu.Lock()
	c, ok := r.etat.Candidats[adresse]
	if !ok {
		r.mu.Unlock()
		return candidat{}, errors.New("inscription inconnue")
	}
	// CONFIRMATION À UN COUP. Une fois confirmé, rien ne se rejoue : ni requête
	// vers le nœud, ni écriture. Avant, n'importe qui lisant l'adresse publique
	// pouvait rappeler confirmer et remettre `Depuis` à maintenant, donc repousser
	// indéfiniment l'admission d'un bénévole honnête (relecture du 24/11, point 5a).
	if c.Confirme {
		copie := *c
		r.mu.Unlock()
		return copie, nil
	}
	defi := c.Defi
	r.mu.Unlock()
	if err := r.verifierDefi(adresse, defi); err != nil {
		return candidat{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok = r.etat.Candidats[adresse]
	if !ok {
		return candidat{}, errors.New("inscription inconnue")
	}
	if !c.Confirme {
		// `Depuis` est MONOTONE : écrit à la seule transition vers Confirme.
		c.Confirme = true
		c.Depuis = r.cfg.Maintenant()
		// Mission 28 : quota journalier décrémenté à la confirmation
		if !c.QuotaPris {
			r.etat.TotalJour++
			c.QuotaPris = true
		}
	}
	// Le défi a servi : effacé, il ne prouve plus rien.
	c.Defi = ""
	if err := r.enregistrer(); err != nil {
		return candidat{}, err
	}
	return *c, nil
}

// sonder interroge un nœud sur tous les domaines et compare à la référence.
// Un RCODE ou un bit AD différent est un mensonge. Pour les adresses A, une
// intersection suffit : les CDN et les tourniquets renvoient légitimement des
// ensembles différents. Un ensemble disjoint sur une réponse signée reste un
// mensonge ; sur une réponse non signée, c'est seulement un doute, identifié
// par une empreinte de domaine (jamais le nom en clair).
func (r *registre) sonder(adresse string, domaines []string) ([]string, error) {
	douteux, _, err := r.sonderAvecMesures(adresse, domaines)
	return douteux, err
}

func (r *registre) sonderAvecMesures(adresse string, domaines []string) ([]string, []mesureSonde, error) {
	url, err := urlNoeud(adresse)
	if err != nil {
		return nil, nil, errIndisponible
	}
	var douteux []string
	var mesures []mesureSonde
	for _, domaine := range domaines {
		// Mission 28 : ID DNS aléatoire pour chaque sonde
		dnsID := uint16(mathrand.Intn(65535) + 1)
		attendu, err := interrogerReference(r.cfg.Reference, domaine)
		if err != nil {
			// Mission 28 : un échec imputable au contrôleur (référence injoignable)
			// n'altère AUCUN compteur du bénévole : la passe est abandonnée.
			return douteux, mesures, fmt.Errorf("référence DNSSEC indisponible")
		}
		debut := time.Now()
		obtenu, _, err := interrogerDoH(r.cfg.Client, url, domaine)
		mesure := mesureSonde{Delai: time.Since(debut), Joignable: err == nil, Correct: err == nil, DnsID: dnsID}
		if err != nil {
			mesures = append(mesures, mesure)
			return douteux, mesures, errIndisponible
		}
		if obtenu.Rcode != attendu.Rcode || obtenu.AD != attendu.AD {
			mesure.Correct = false
			mesures = append(mesures, mesure)
			return douteux, mesures, errMensonge
		}
		if len(attendu.IPs) == 0 && len(obtenu.IPs) == 0 {
			mesures = append(mesures, mesure)
			continue
		}
		if intersection(attendu.IPs, obtenu.IPs) {
			mesures = append(mesures, mesure)
			continue
		}
		if attendu.AD || obtenu.AD {
			mesure.Correct = false
			mesures = append(mesures, mesure)
			return douteux, mesures, errMensonge
		}
		mesures = append(mesures, mesure)
		douteux = append(douteux, empreinteDomaine(domaine))
	}
	return douteux, mesures, nil
}

func auMoinsJoignable(mesures []mesureSonde) bool {
	for _, mesure := range mesures {
		if mesure.Joignable {
			return true
		}
	}
	return false
}

// intersection compare deux listes triées d'adresses sans allouer de map.
func intersection(a, b []string) bool {
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		switch {
		case a[i] == b[j]:
			return true
		case a[i] < b[j]:
			i++
		default:
			j++
		}
	}
	return false
}

// empreinteDomaine permet de compter les doutes sur des domaines distincts
// sans conserver ni journaliser les noms testés.
func empreinteDomaine(domaine string) string {
	somme := sha256.Sum256([]byte(strings.ToLower(strings.TrimSuffix(domaine, "."))))
	return hex.EncodeToString(somme[:8])
}

func ajouterDoutes(doutes map[string]time.Time, domaines []string, maintenant time.Time) map[string]time.Time {
	if doutes == nil {
		doutes = map[string]time.Time{}
	}
	for _, domaine := range domaines {
		doutes[domaine] = maintenant
	}
	return doutes
}

// passe sonde tous les nœuds une fois. Renvoie vrai si l'ensemble des admis a
// changé (une régénération du pool communauté est alors nécessaire).
func (r *registre) passe() (bool, error) {
	r.mu.Lock()
	maintenant := r.cfg.Maintenant()
	r.changerJour(maintenant)
	adresses := make([]string, 0, len(r.etat.Candidats)+len(r.etat.Admis))
	for a := range r.etat.Candidats {
		adresses = append(adresses, a)
	}
	for a := range r.etat.Admis {
		adresses = append(adresses, a)
	}
	r.mu.Unlock()
	sort.Strings(adresses)
	// Un sous-ensemble aléatoire de la liste publique à chaque passe : un nœud
	// ne peut pas savoir quels domaines seront testés.
	domaines := append([]string(nil), r.cfg.Domaines...)
	mathrand.Shuffle(len(domaines), func(i, j int) { domaines[i], domaines[j] = domaines[j], domaines[i] })
	if len(domaines) > r.cfg.DomainesParPasse {
		domaines = domaines[:r.cfg.DomainesParPasse]
	}

	change := false
	for _, adresse := range adresses {
		r.mu.Lock()
		c, candidat := r.etat.Candidats[adresse]
		confirme := candidat && c.Confirme
		r.mu.Unlock()
		if candidat && !confirme {
			continue
		}
		douteux, mesures, err := r.sonderAvecMesures(adresse, domaines)
		r.reseau.ajouterSonde(categorieCommunaute, adresse, mesures, auMoinsJoignable(mesures), maintenant)
		r.mu.Lock()
		if c, ok := r.etat.Candidats[adresse]; ok {
			if err != nil {
				if errors.Is(err, errMensonge) {
					// Un mensonge DNSSEC pendant la quarantaine disqualifie.
					delete(r.etat.Candidats, adresse)
				} else if errors.Is(err, errIndisponible) {
					// Mission 28 : un échec imputable au contrôleur n'altère AUCUN compteur.
					// On ne fait rien, la passe pour ce nœud est abandonnée silencieusement.
				} else {
					c.SondesKO++
					c.DernierKO = maintenant
					// Mission 28 : les indisponibilités « consécutives » se remettent à zéro après un succès.
					// Si on n'a jamais eu de succès (DernierOK.IsZero()), on garde le comportement existant.
					if c.DernierOK.IsZero() {
						c.Depuis = maintenant
						c.SondesOK = 0
					}
				}
			} else if len(douteux) > 0 {
				c.Doutes = ajouterDoutes(c.Doutes, douteux, maintenant)
				if len(c.Doutes) >= r.cfg.DoutesMax {
					// N domaines distincts divergents : le candidat n'est pas
					// fiable, même si chaque écart pris seul pouvait être un CDN.
					delete(r.etat.Candidats, adresse)
				}
			} else {
				c.SondesOK++
				c.DernierOK = maintenant
				if maintenant.Sub(c.Depuis) >= r.cfg.Quarantaine && c.SondesOK >= r.cfg.SondesMin {
					delete(r.etat.Candidats, adresse)
					r.etat.Admis[adresse] = &admis{
						Adresse:    adresse,
						Depuis:     maintenant,
						SondesOK:   c.SondesOK,
						Disponible: 1,
						DernierOK:  maintenant,
					}
					change = true
				}
			}
		} else if a, ok := r.etat.Admis[adresse]; ok {
			total := a.SondesOK + a.SondesKO
			if err != nil {
				if errors.Is(err, errIndisponible) {
					// Mission 28 : un échec imputable au contrôleur n'altère AUCUN compteur.
					// On ne fait rien.
				} else {
					a.SondesKO++
					if errors.Is(err, errMensonge) && a.SondesKO >= r.cfg.EchecsMax ||
						errors.Is(err, errIndisponible) && a.SondesKO >= r.cfg.IndispoMax {
						delete(r.etat.Admis, adresse)
						r.etat.Evinces[adresse] = maintenant
						change = true
					}
				}
			} else if len(douteux) > 0 {
				a.Doutes = ajouterDoutes(a.Doutes, douteux, maintenant)
				if len(a.Doutes) >= r.cfg.DoutesMax {
					delete(r.etat.Admis, adresse)
					r.etat.Evinces[adresse] = maintenant
					change = true
				}
			} else {
				a.SondesOK++
				a.DernierOK = maintenant
				// Mission 28 : remise à zéro des indisponibilités consécutives après un succès
			}
			if t := a.SondesOK + a.SondesKO; t > 0 {
				a.Disponible = float64(a.SondesOK) / float64(t)
			} else {
				a.Disponible = float64(a.SondesOK) / float64(total)
			}
		}
		r.mu.Unlock()
	}
	// Le pool cœur ne participe pas à l'admission, mais ses sondes alimentent
	// le même état public. Une adresse retirée du pool disparaît des compteurs
	// au prochain chargement du fichier.
	r.mu.Lock()
	r.coeur = r.lireCoeur()
	coeur := append([]string(nil), r.coeur...)
	r.mu.Unlock()
	for _, adresse := range coeur {
		_, mesures, err := r.sonderAvecMesures(adresse, domaines)
		r.reseau.ajouterSonde(categorieCoeur, adresse, mesures, auMoinsJoignable(mesures), maintenant)
		_ = err
	}
	r.mu.Lock()
	err := r.enregistrer()
	r.mu.Unlock()
	if err == nil && change {
		if err = r.ecrirePool(); err != nil {
			return true, err
		}
	}
	if err == nil && change && r.cfg.Hook != nil {
		r.cfg.Hook()
	}
	if err == nil {
		if errPub := r.publierReseau(maintenant); errPub != nil {
			return change, errPub
		}
	}
	return change, err
}

// lireCoeur relit le pool cœur à chaque passe : l'administrateur peut le
// modifier sans redémarrer le registre. Les lignes vides et commentaires sont
// ignorés ; une adresse invalide ne peut pas entrer dans les sondes.
func (r *registre) lireCoeur() []string {
	if r.cfg.CoeurFichier == "" {
		return nil
	}
	brut, err := os.ReadFile(r.cfg.CoeurFichier)
	if err != nil {
		return nil
	}
	var adresses []string
	for _, ligne := range strings.Split(string(brut), "\n") {
		ligne = strings.TrimSpace(ligne)
		if ligne == "" || strings.HasPrefix(ligne, "#") || !reAdresse.MatchString(ligne) {
			continue
		}
		adresses = append(adresses, ligne)
	}
	sort.Strings(adresses)
	return adresses
}

// ecrirePool publie le pool communauté à partir des seuls nœuds admis. Le
// pool cœur n'est jamais écrit ici.
func (r *registre) ecrirePool() error {
	if r.cheminPool == "" {
		return nil
	}
	r.mu.Lock()
	adresses := make([]string, 0, len(r.etat.Admis))
	for a := range r.etat.Admis {
		adresses = append(adresses, a)
	}
	r.mu.Unlock()
	sort.Strings(adresses)
	var b strings.Builder
	b.WriteString("# TorDNS — pool communauté, écrit par le registre. Ne pas modifier.\n")
	for _, a := range adresses {
		b.WriteString(a)
		b.WriteByte('\n')
	}
	if err := os.MkdirAll(filepath.Dir(r.cheminPool), 0o700); err != nil {
		return err
	}
	tmp := r.cheminPool + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, r.cheminPool)
}

func (r *registre) instantane() etat {
	r.mu.Lock()
	defer r.mu.Unlock()
	copie := etat{
		Candidats: map[string]*candidat{},
		Admis:     map[string]*admis{},
		Evinces:   map[string]time.Time{},
		Jour:      r.etat.Jour,
		TotalJour: r.etat.TotalJour,
	}
	for k, v := range r.etat.Candidats {
		c := *v
		// /etat est public (relecture du 23/11) : ni le contact du bénévole,
		// ni le défi (il ne sert qu'au nœud qui s'inscrit), ni les empreintes
		// des domaines de sondage.
		c.Contact = ""
		c.Defi = ""
		c.Doutes = nil
		copie.Candidats[k] = &c
	}
	for k, v := range r.etat.Admis {
		a := *v
		a.Doutes = nil
		copie.Admis[k] = &a
	}
	for k, v := range r.etat.Evinces {
		copie.Evinces[k] = v
	}
	return copie
}

// normaliser rend la forme canonique d'une adresse d'instance, seule clé admise
// pour lire ou écrire l'état (candidats, admis, évincés).
func (r *registre) normaliser(adresse string) (string, bool) {
	a := strings.ToLower(strings.TrimSpace(adresse))
	if reOnion.MatchString(a) {
		return a, true
	}
	if r.cfg.AdressesLocales {
		if m := reLocale.FindStringSubmatch(a); m != nil {
			port, err := strconv.Atoi(m[2])
			if err != nil || port < 1 || port > 65535 {
				return "", false
			}
			return "127.0.0.1:" + strconv.Itoa(port), true
		}
	}
	return "", false
}
