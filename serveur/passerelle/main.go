// TorDNS — passerelle DoH (RFC 8484).
//
// Reçoit du DNS filaire en HTTP et le transmet à Unbound sur le réseau docker
// privé. Aucune requête n'est journalisée : les erreurs HTTP sont elles aussi
// jetées, et le serveur ne conserve aucune trace des questions reçues.
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	tailleMaxRequete = 4096
	tailleMaxReponse = 65535
)

// resolveur interroge Unbound en UDP, puis en TCP si la réponse est tronquée.
type resolveur struct {
	adresse string
	delai   time.Duration
}

func (r *resolveur) Resoudre(message []byte) ([]byte, error) {
	reponse, err := r.questionUDP(message)
	if err == nil && !estTronquee(reponse) {
		return reponse, nil
	}
	return r.questionTCP(message)
}

func (r *resolveur) questionUDP(message []byte) ([]byte, error) {
	conn, err := net.DialTimeout("udp", r.adresse, r.delai)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(r.delai)); err != nil {
		return nil, err
	}
	if _, err := conn.Write(message); err != nil {
		return nil, err
	}
	tampon := make([]byte, tailleMaxReponse)
	n, err := conn.Read(tampon)
	if err != nil {
		return nil, err
	}
	return tampon[:n], nil
}

func (r *resolveur) questionTCP(message []byte) ([]byte, error) {
	conn, err := net.DialTimeout("tcp", r.adresse, r.delai)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(r.delai)); err != nil {
		return nil, err
	}

	entete := make([]byte, 2)
	binary.BigEndian.PutUint16(entete, uint16(len(message)))
	if _, err := conn.Write(append(entete, message...)); err != nil {
		return nil, err
	}

	if _, err := io.ReadFull(conn, entete); err != nil {
		return nil, err
	}
	taille := int(binary.BigEndian.Uint16(entete))
	if taille < 12 || taille > tailleMaxReponse {
		return nil, errors.New("réponse TCP de taille invalide")
	}
	reponse := make([]byte, taille)
	if _, err := io.ReadFull(conn, reponse); err != nil {
		return nil, err
	}
	return reponse, nil
}

func estTronquee(message []byte) bool {
	return len(message) >= 4 && message[2]&0x02 != 0
}

func main() {
	adresseUnbound := env("UNBOUND_ADDR", "unbound:5335")
	adresseEcoute := env("LISTEN_ADDR", ":8053")

	r := &resolveur{adresse: adresseUnbound, delai: 5 * time.Second}
	limiteur := nouveauLimiteur(envNombre("LIMITE_REQ_S", 200), envNombre("LIMITE_RAFALE", 400))
	concurrence := make(chan struct{}, int(envNombre("MAX_CONCURRENTS", 64)))

	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", func(w http.ResponseWriter, req *http.Request) {
		// Limite globale : derrière un service caché Tor, toutes les requêtes
		// arrivent de la même IP (celle de Tor), une limite par IP serait donc
		// inopérante ou injuste. On borne le débit total et le parallélisme.
		if !limiteur.autoriser() {
			rejetTemporaire(w)
			return
		}
		select {
		case concurrence <- struct{}{}:
			defer func() { <-concurrence }()
		default:
			rejetTemporaire(w)
			return
		}
		servirDoH(w, req, r)
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, req *http.Request) {
		sonde(w, req, r)
	})

	serveur := &http.Server{
		Addr:              adresseEcoute,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		// Aucune erreur HTTP (URL, en-têtes) ne doit finir dans un journal.
		ErrorLog: log.New(io.Discard, "", 0),
	}

	if err := serveur.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(os.Stderr, "passerelle: arrêt:", err)
		os.Exit(1)
	}
}

func env(cle, defaut string) string {
	if v := os.Getenv(cle); v != "" {
		return v
	}
	return defaut
}

func envNombre(cle string, defaut float64) float64 {
	v, err := strconv.ParseFloat(os.Getenv(cle), 64)
	if err != nil || v < 1 {
		return defaut
	}
	return v
}

// --- Limitation de débit (seau à jetons) ---

type limiteurDebit struct {
	mu      sync.Mutex
	debit   float64 // jetons ajoutés par seconde
	rafale  float64 // capacité maximale du seau
	jetons  float64
	instant time.Time
}

func nouveauLimiteur(debit, rafale float64) *limiteurDebit {
	return &limiteurDebit{debit: debit, rafale: rafale, jetons: rafale, instant: time.Now()}
}

func (l *limiteurDebit) autoriser() bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	maintenant := time.Now()
	l.jetons += maintenant.Sub(l.instant).Seconds() * l.debit
	if l.jetons > l.rafale {
		l.jetons = l.rafale
	}
	l.instant = maintenant
	if l.jetons < 1 {
		return false
	}
	l.jetons--
	return true
}

func rejetTemporaire(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "1")
	erreurHTTP(w, http.StatusTooManyRequests)
}

// sonde répond sans journaliser ni exposer de données client : elle effectue
// une résolution fixe (example.com A) pour vérifier la chaîne Unbound + DNSSEC.
func sonde(w http.ResponseWriter, req *http.Request, r *resolveur) {
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		erreurHTTP(w, http.StatusMethodNotAllowed)
		return
	}
	message, err := messageRequete("example.com", 1)
	if err != nil {
		erreurHTTP(w, http.StatusServiceUnavailable)
		return
	}
	reponse, err := r.Resoudre(message)
	if err != nil || len(reponse) < 12 || reponse[3]&0x0F != 0 {
		erreurHTTP(w, http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, "ok\n")
}

func servirDoH(w http.ResponseWriter, req *http.Request, r *resolveur) {
	if req.URL.Path != "/dns-query" {
		http.NotFound(w, req)
		return
	}

	switch req.Method {
	case http.MethodGet:
		servirGet(w, req, r)
	case http.MethodPost:
		servirPost(w, req, r)
	default:
		w.Header().Set("Allow", "GET, POST")
		erreurHTTP(w, http.StatusMethodNotAllowed)
	}
}

// GET /dns-query?dns=<base64url du message DNS> (RFC 8484 §4.1).
// Variante lisible, non normalisée : ?name=example.com&type=A avec
// Accept: application/dns-json.
func servirGet(w http.ResponseWriter, req *http.Request, r *resolveur) {
	params := req.URL.Query()

	if valeur := params.Get("dns"); valeur != "" {
		message, err := decoderBase64URL(valeur)
		if err != nil || len(message) < 12 || len(message) > tailleMaxRequete {
			erreurHTTP(w, http.StatusBadRequest)
			return
		}
		repondreFilaire(w, r, message)
		return
	}

	nom := params.Get("name")
	accepte := strings.ToLower(req.Header.Get("Accept"))
	if nom != "" && strings.Contains(accepte, "application/dns-json") {
		repondreJSON(w, r, nom, params.Get("type"))
		return
	}

	erreurHTTP(w, http.StatusBadRequest)
}

func servirPost(w http.ResponseWriter, req *http.Request, r *resolveur) {
	mediaType, _, err := mime.ParseMediaType(req.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/dns-message" {
		erreurHTTP(w, http.StatusUnsupportedMediaType)
		return
	}

	corps, err := io.ReadAll(io.LimitReader(req.Body, tailleMaxRequete+1))
	if err != nil || len(corps) < 12 || len(corps) > tailleMaxRequete {
		erreurHTTP(w, http.StatusBadRequest)
		return
	}

	repondreFilaire(w, r, corps)
}

func decoderBase64URL(valeur string) ([]byte, error) {
	if message, err := base64.RawURLEncoding.DecodeString(valeur); err == nil {
		return message, nil
	}
	return base64.URLEncoding.DecodeString(valeur)
}

func repondreFilaire(w http.ResponseWriter, r *resolveur, message []byte) {
	reponse, err := r.Resoudre(message)
	if err != nil {
		erreurHTTP(w, http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", fmt.Sprint(len(reponse)))
	_, _ = w.Write(reponse)
}

func repondreJSON(w http.ResponseWriter, r *resolveur, nom, typeTexte string) {
	qtype, ok := typeDNS(typeTexte)
	if !ok {
		erreurHTTP(w, http.StatusBadRequest)
		return
	}
	message, err := messageRequete(nom, qtype)
	if err != nil {
		erreurHTTP(w, http.StatusBadRequest)
		return
	}
	reponse, err := r.Resoudre(message)
	if err != nil {
		erreurHTTP(w, http.StatusBadGateway)
		return
	}
	resultat, err := lireReponse(reponse)
	if err != nil {
		erreurHTTP(w, http.StatusBadGateway)
		return
	}
	corps, err := json.Marshal(resultat)
	if err != nil {
		erreurHTTP(w, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/dns-json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(corps)
}

func erreurHTTP(w http.ResponseWriter, code int) {
	http.Error(w, http.StatusText(code), code)
}

var typesDNS = map[string]uint16{
	"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16,
	"AAAA": 28, "SRV": 33, "DNAME": 39, "DS": 43, "RRSIG": 46, "NSEC": 47,
	"DNSKEY": 48, "NSEC3": 50, "TLSA": 52, "CAA": 257,
}

func typeDNS(texte string) (uint16, bool) {
	if texte == "" {
		return 1, true
	}
	if t, ok := typesDNS[strings.ToUpper(texte)]; ok {
		return t, true
	}
	return 0, false
}

// --- Construction et lecture des messages DNS (format filaire) ---

func messageRequete(nom string, qtype uint16) ([]byte, error) {
	nom = strings.TrimSpace(nom)
	nom = strings.TrimSuffix(nom, ".")
	qname := make([]byte, 0, len(nom)+2)
	if nom != "" {
		for _, label := range strings.Split(nom, ".") {
			if len(label) == 0 || len(label) > 63 {
				return nil, errors.New("nom DNS invalide")
			}
			qname = append(qname, byte(len(label)))
			qname = append(qname, label...)
		}
	}
	qname = append(qname, 0)
	if len(qname) > 255 {
		return nil, errors.New("nom DNS trop long")
	}

	identifiant := make([]byte, 2)
	if _, err := rand.Read(identifiant); err != nil {
		return nil, err
	}

	message := make([]byte, 12, 12+len(qname)+4+11)
	copy(message, identifiant)
	message[2] = 0x01                             // RD : récursion demandée
	binary.BigEndian.PutUint16(message[4:6], 1)   // une question
	binary.BigEndian.PutUint16(message[10:12], 1) // un enregistrement additionnel : OPT

	message = append(message, qname...)
	message = binary.BigEndian.AppendUint16(message, qtype)
	message = binary.BigEndian.AppendUint16(message, 1) // classe IN

	// OPT (EDNS0) avec le bit DO : on demande la validation DNSSEC pour
	// pouvoir exposer le bit AD dans la réponse JSON.
	message = append(message, 0)                           // racine
	message = binary.BigEndian.AppendUint16(message, 41)   // type OPT
	message = binary.BigEndian.AppendUint16(message, 1232) // taille UDP
	message = binary.BigEndian.AppendUint32(message, 0x00008000)
	message = binary.BigEndian.AppendUint16(message, 0) // pas de données
	return message, nil
}

type questionJSON struct {
	Name string `json:"name"`
	Type int    `json:"type"`
}

type rrJSON struct {
	Name string `json:"name"`
	Type int    `json:"type"`
	TTL  uint32 `json:"TTL"`
	Data string `json:"data"`
}

type reponseJSON struct {
	Status   int            `json:"Status"`
	TC       bool           `json:"TC"`
	RD       bool           `json:"RD"`
	RA       bool           `json:"RA"`
	AD       bool           `json:"AD"`
	CD       bool           `json:"CD"`
	Question []questionJSON `json:"Question,omitempty"`
	Answer   []rrJSON       `json:"Answer,omitempty"`
}

func lireReponse(message []byte) (*reponseJSON, error) {
	if len(message) < 12 {
		return nil, errors.New("réponse DNS tronquée")
	}
	drapeaux := binary.BigEndian.Uint16(message[2:4])
	reponse := &reponseJSON{
		Status: int(drapeaux & 0x000F),
		TC:     drapeaux&0x0200 != 0,
		RD:     drapeaux&0x0100 != 0,
		RA:     drapeaux&0x0080 != 0,
		AD:     drapeaux&0x0020 != 0,
		CD:     drapeaux&0x0010 != 0,
	}

	qdcount := int(binary.BigEndian.Uint16(message[4:6]))
	ancount := int(binary.BigEndian.Uint16(message[6:8]))
	position := 12

	for i := 0; i < qdcount; i++ {
		nom, apres, err := lireNom(message, position)
		if err != nil || apres+4 > len(message) {
			return nil, errors.New("question DNS invalide")
		}
		reponse.Question = append(reponse.Question, questionJSON{
			Name: nom,
			Type: int(binary.BigEndian.Uint16(message[apres : apres+2])),
		})
		position = apres + 4
	}

	for i := 0; i < ancount; i++ {
		rr, apres, err := lireRR(message, position)
		if err != nil {
			return nil, err
		}
		reponse.Answer = append(reponse.Answer, rr)
		position = apres
	}

	return reponse, nil
}

// lireNom décode un nom DNS (labels + pointeurs de compression) et renvoie le
// nom absolu ainsi que la position qui suit le nom dans le flux d'origine.
func lireNom(message []byte, position int) (string, int, error) {
	var labels []string
	longueur := 0
	suivant := -1
	sauts := 0

	for {
		if position >= len(message) {
			return "", 0, errors.New("nom DNS tronqué")
		}
		octet := int(message[position])

		switch {
		case octet == 0:
			position++
			if suivant < 0 {
				suivant = position
			}
			if len(labels) == 0 {
				return ".", suivant, nil
			}
			return strings.Join(labels, ".") + ".", suivant, nil

		case octet&0xC0 == 0xC0:
			if position+1 >= len(message) {
				return "", 0, errors.New("pointeur de compression tronqué")
			}
			pointeur := int(binary.BigEndian.Uint16(message[position:position+2]) & 0x3FFF)
			if suivant < 0 {
				suivant = position + 2
			}
			sauts++
			if sauts > 64 || pointeur >= len(message) {
				return "", 0, errors.New("pointeur de compression invalide")
			}
			position = pointeur

		case octet&0xC0 != 0:
			return "", 0, errors.New("label DNS invalide")

		default:
			if position+1+octet > len(message) {
				return "", 0, errors.New("label DNS tronqué")
			}
			longueur += octet + 1
			if longueur > 255 {
				return "", 0, errors.New("nom DNS trop long")
			}
			labels = append(labels, string(message[position+1:position+1+octet]))
			position += 1 + octet
		}
	}
}

func lireRR(message []byte, position int) (rrJSON, int, error) {
	nom, apres, err := lireNom(message, position)
	if err != nil {
		return rrJSON{}, 0, err
	}
	if apres+10 > len(message) {
		return rrJSON{}, 0, errors.New("enregistrement DNS tronqué")
	}
	typ := binary.BigEndian.Uint16(message[apres : apres+2])
	ttl := binary.BigEndian.Uint32(message[apres+4 : apres+8])
	rdlength := int(binary.BigEndian.Uint16(message[apres+8 : apres+10]))
	debut := apres + 10
	if debut+rdlength > len(message) {
		return rrJSON{}, 0, errors.New("données DNS tronquées")
	}

	donnees, err := formaterDonnees(message, debut, rdlength, typ)
	if err != nil {
		return rrJSON{}, 0, err
	}
	return rrJSON{Name: nom, Type: int(typ), TTL: ttl, Data: donnees}, debut + rdlength, nil
}

func formaterDonnees(message []byte, debut, longueur int, typ uint16) (string, error) {
	donnees := message[debut : debut+longueur]

	switch typ {
	case 1: // A
		if len(donnees) != 4 {
			return "", errors.New("A invalide")
		}
		return net.IP(donnees).String(), nil
	case 28: // AAAA
		if len(donnees) != 16 {
			return "", errors.New("AAAA invalide")
		}
		return net.IP(donnees).String(), nil
	case 2, 5, 12, 39: // NS, CNAME, PTR, DNAME
		nom, _, err := lireNom(message, debut)
		return nom, err
	case 15: // MX
		if longueur < 3 {
			return "", errors.New("MX invalide")
		}
		priorite := binary.BigEndian.Uint16(donnees[:2])
		nom, _, err := lireNom(message, debut+2)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%d %s", priorite, nom), nil
	case 16: // TXT
		return formaterTXT(donnees)
	case 6: // SOA
		return formaterSOA(message, debut)
	default:
		return fmt.Sprintf("\\# %d %s", longueur, hex.EncodeToString(donnees)), nil
	}
}

func formaterTXT(donnees []byte) (string, error) {
	var morceaux []string
	for i := 0; i < len(donnees); {
		taille := int(donnees[i])
		i++
		if i+taille > len(donnees) {
			return "", errors.New("TXT invalide")
		}
		texte := strings.ReplaceAll(string(donnees[i:i+taille]), `\`, `\\`)
		texte = strings.ReplaceAll(texte, `"`, `\"`)
		morceaux = append(morceaux, `"`+texte+`"`)
		i += taille
	}
	return strings.Join(morceaux, " "), nil
}

func formaterSOA(message []byte, debut int) (string, error) {
	mname, apres, err := lireNom(message, debut)
	if err != nil {
		return "", err
	}
	rname, apres, err := lireNom(message, apres)
	if err != nil {
		return "", err
	}
	if apres+20 > len(message) {
		return "", errors.New("SOA tronqué")
	}
	valeurs := make([]string, 0, 5)
	for i := 0; i < 5; i++ {
		valeurs = append(valeurs, fmt.Sprint(binary.BigEndian.Uint32(message[apres+4*i:apres+4*i+4])))
	}
	return fmt.Sprintf("%s %s %s", mname, rname, strings.Join(valeurs, " ")), nil
}
