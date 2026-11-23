// Paquet relais : cœur portable du client TorDNS (Linux et macOS).
//
// Il ne connaît ni systemd, ni launchd, ni resolv.conf : l'hôte fournit
// l'adresse d'écoute et les chemins de configuration, puis appelle Traiter.
package relais

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync/atomic"
	"time"
)

// Options décrit le relais. Les zéros sont remplacés par des valeurs sûres.
type Options struct {
	Onion       string
	SOCKS       string
	TailleCache int
	TTLMax      time.Duration
	Delai       time.Duration
	Concurrence int
	DNSSEC      string // non, auto (défaut) ou strict
}

type config struct {
	onion       string
	socks       string
	tailleCache int
	ttlMax      time.Duration
	delai       time.Duration
	concurrence int
}

// Relais est un relais DNS local. Ses méthodes sont sûres pour un usage
// concurrent ; les compteurs sont atomiques.
type Relais struct {
	cfg      config
	cache    *cache
	doh      *clientDoH
	requetes atomic.Uint64
	hits     atomic.Uint64
	erreurs  atomic.Uint64
	dnssec   string
	valider  func([]byte) error
}

// Nouveau construit le relais et sa chaîne DNSSEC. Aucun échange réseau n'a
// lieu ici : le proxy SOCKS est vérifié séparément par l'hôte.
func Nouveau(o Options) (*Relais, error) {
	if o.TailleCache <= 0 {
		o.TailleCache = 4096
	}
	if o.TTLMax <= 0 {
		o.TTLMax = time.Hour
	}
	if o.Delai <= 0 {
		o.Delai = 10 * time.Second
	}
	if o.Concurrence <= 0 {
		o.Concurrence = 64
	}
	if o.DNSSEC == "" {
		o.DNSSEC = "auto"
	}
	if o.DNSSEC != "non" && o.DNSSEC != "auto" && o.DNSSEC != "strict" {
		return nil, fmt.Errorf("mode DNSSEC inconnu %q : non, auto ou strict", o.DNSSEC)
	}
	r := &Relais{
		cfg: config{
			onion:       o.Onion,
			socks:       o.SOCKS,
			tailleCache: o.TailleCache,
			ttlMax:      o.TTLMax,
			delai:       o.Delai,
			concurrence: o.Concurrence,
		},
		cache:  nouveauCache(o.TailleCache),
		doh:    nouveauClientDoH(o.Onion, o.SOCKS, o.Delai, o.Concurrence),
		dnssec: o.DNSSEC,
	}
	if o.DNSSEC != "non" {
		v, err := nouveauValidateur(r.brut, ancreRacineDS)
		if err != nil {
			return nil, fmt.Errorf("initialisation DNSSEC : %w", err)
		}
		r.valider = v.Valider
	}
	return r, nil
}

// ProxyJoignable vérifie que le SOCKS local répond avant de démarrer. Le
// client ne doit jamais retomber en DNS clair si Tor est absent.
func ProxyJoignable(socks string, delai time.Duration) error {
	if socks == "" {
		return errors.New("proxy SOCKS vide")
	}
	if delai <= 0 {
		delai = 3 * time.Second
	}
	conn, err := net.DialTimeout("tcp", socks, delai)
	if err != nil {
		return fmt.Errorf("proxy SOCKS %s injoignable : %w", socks, err)
	}
	return conn.Close()
}

// ModeValide indique si le mode d'adresse est connu.
func ModeValide(mode string) bool { return modeValide(mode) }

// AdresseEffective combine le manifeste signé, le mode et l'adresse de secours.
func AdresseEffective(dossier, cle, mode, secours string) string {
	return adresseEffective(dossier, cle, mode, secours)
}

// ClePublique lit la clé de publication surchargeable (tests, rotation).
func ClePublique() string { return clePublique() }

// Traiter répond à une requête DNS : cache d'abord, puis DoH via Tor. Une
// requête illisible est ignorée ; une panne du relais devient un SERVFAIL.
func (r *Relais) Traiter(msg []byte) []byte {
	q, err := analyser(msg)
	if err != nil {
		return nil
	}
	r.requetes.Add(1)
	cle := q.cle()
	if rep, age, ok := r.cache.obtenir(cle); ok {
		r.hits.Add(1)
		return ajuster(rep, q.id, age)
	}
	rep, err := r.interroger(msg)
	if err != nil {
		r.erreurs.Add(1)
		log.Printf("erreur de résolution (type %d) : %v", q.qtype, err)
		return servfail(msg)
	}
	if r.valider != nil {
		err := r.valider(rep)
		if errors.Is(err, ErrZoneNonSignee) && r.dnssec == "auto" {
			// Zone non signée : comportement normal, aucune garantie DNSSEC.
		} else if err != nil {
			r.erreurs.Add(1)
			log.Printf("réponse refusée par DNSSEC (type %d) : %v", q.qtype, err)
			return servfail(msg)
		}
	}
	if ttl, ok := cacheable(rep, r.cfg.ttlMax); ok {
		r.cache.poser(cle, rep, ttl)
	}
	return ajuster(rep, q.id, 0)
}

// interroger tente une résolution, puis une seule fois de plus en cas de
// connexion morte réutilisée depuis le pool.
func (r *Relais) interroger(msg []byte) ([]byte, error) {
	return r.brut(msg)
}

// brut envoie une requête sans validation DNSSEC : c'est le chemin utilisé
// pour construire la chaîne d'ancrage elle-même.
func (r *Relais) brut(msg []byte) ([]byte, error) {
	var derniere error
	for essai := 0; essai < 2; essai++ {
		cn, err := r.doh.emprunter()
		if err != nil {
			derniere = err
			continue
		}
		rep, err := r.doh.poster(cn, msg)
		if err != nil {
			cn.Close()
			derniere = err
			continue
		}
		if err := verifierReponse(msg, rep); err != nil {
			cn.Close()
			derniere = err
			continue
		}
		r.doh.rendre(cn)
		return rep, nil
	}
	return nil, derniere
}

// ServirUDP sert les requêtes UDP jusqu'à la fermeture de la connexion.
func (r *Relais) ServirUDP(conn *net.UDPConn) {
	sem := make(chan struct{}, r.cfg.concurrence)
	tampon := make([]byte, 4096)
	for {
		n, adresse, err := conn.ReadFromUDP(tampon)
		if err != nil {
			return
		}
		msg := append([]byte(nil), tampon[:n]...)
		select {
		case sem <- struct{}{}:
		default: // saturation : on abandonne la requête plutôt que d'accumuler
			continue
		}
		go func() {
			defer func() { <-sem }()
			if rep := r.Traiter(msg); rep != nil {
				_, _ = conn.WriteToUDP(rep, adresse)
			}
		}()
	}
}

// ServirTCP sert les connexions TCP jusqu'à la fermeture de l'écoute.
func (r *Relais) ServirTCP(ecoute *net.TCPListener) {
	for {
		conn, err := ecoute.Accept()
		if err != nil {
			return
		}
		go r.connexionTCP(conn)
	}
}

// connexionTCP sert plusieurs requêtes sur la même connexion (RFC 7766),
// chacune préfixée par sa longueur sur deux octets.
func (r *Relais) connexionTCP(conn net.Conn) {
	defer conn.Close()
	lecteur := bufio.NewReader(conn)
	for {
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
		var entete [2]byte
		if _, err := io.ReadFull(lecteur, entete[:]); err != nil {
			return
		}
		longueur := int(binary.BigEndian.Uint16(entete[:]))
		if longueur < 12 {
			return
		}
		msg := make([]byte, longueur)
		if _, err := io.ReadFull(lecteur, msg); err != nil {
			return
		}
		rep := r.Traiter(msg)
		if rep == nil {
			return
		}
		binary.BigEndian.PutUint16(entete[:], uint16(len(rep)))
		ecrivain := bufio.NewWriter(conn)
		if _, err := ecrivain.Write(entete[:]); err != nil {
			return
		}
		if _, err := ecrivain.Write(rep); err != nil {
			return
		}
		if err := ecrivain.Flush(); err != nil {
			return
		}
	}
}

// Stats retourne requêtes, réponses servies par le cache et erreurs.
func (r *Relais) Stats() (uint64, uint64, uint64) {
	return r.requetes.Load(), r.hits.Load(), r.erreurs.Load()
}
