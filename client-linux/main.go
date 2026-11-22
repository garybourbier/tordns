// tordns-client : relais DNS local TorDNS.
//
// Écoute les requêtes DNS classiques (UDP et TCP, 127.0.0.1:53 par défaut),
// les met en cache en mémoire et les transporte vers le service caché Tor v3
// en DoH (RFC 8484) à travers le proxy SOCKS5 d'un démon Tor local. Aucune
// requête DNS directe, aucun journal de requête, rien sur disque.
package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"
)

type config struct {
	ecoute      string
	socks       string
	onion       string
	tailleCache int
	ttlMax      time.Duration
	delai       time.Duration
	concurrence int
	diagnostic  bool
	racine      string
}

type relais struct {
	cfg      config
	cache    *cache
	doh      *clientDoH
	requetes atomic.Uint64
	hits     atomic.Uint64
	erreurs  atomic.Uint64
}

func envOu(cle, defaut string) string {
	if v := os.Getenv(cle); v != "" {
		return v
	}
	return defaut
}

func envEntier(cle string, defaut int) int {
	v, err := strconv.Atoi(os.Getenv(cle))
	if err != nil || v < 1 {
		return defaut
	}
	return v
}

func chargerConfig() config {
	cfg := config{
		ecoute:      envOu("TORDNS_ECOUTE", "127.0.0.1:53"),
		socks:       envOu("TORDNS_SOCKS", "127.0.0.1:9050"),
		onion:       envOu("TORDNS_ONION", ""),
		tailleCache: envEntier("TORDNS_CACHE", 4096),
	}
	flag.StringVar(&cfg.ecoute, "ecoute", cfg.ecoute, "adresse et port d'écoute (UDP et TCP)")
	flag.StringVar(&cfg.socks, "socks", cfg.socks, "adresse du proxy SOCKS5 de Tor")
	flag.StringVar(&cfg.onion, "onion", cfg.onion, "adresse du service caché TorDNS")
	flag.IntVar(&cfg.tailleCache, "cache", cfg.tailleCache, "nombre maximal d'entrées en cache")
	ttlMax := flag.Int("ttl-max", 3600, "durée maximale de mise en cache, en secondes")
	delai := flag.Duration("delai", 10*time.Second, "délai maximal par requête DoH")
	flag.IntVar(&cfg.concurrence, "concurrence", 64, "requêtes simultanées au maximum")
	flag.BoolVar(&cfg.diagnostic, "diagnostic", false, "inspecte les fuites DNS et quitte sans démarrer le relais")
	flag.StringVar(&cfg.racine, "racine", "/", "racine d'inspection du diagnostic (tests)")
	flag.Parse()
	cfg.ttlMax = time.Duration(*ttlMax) * time.Second
	cfg.delai = *delai
	return cfg
}

// traiter répond à une requête DNS : cache d'abord, puis DoH via Tor. Une
// requête illisible est ignorée ; une panne du relais devient un SERVFAIL.
func (r *relais) traiter(msg []byte) []byte {
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
	if ttl, ok := cacheable(rep, r.cfg.ttlMax); ok {
		r.cache.poser(cle, rep, ttl)
	}
	return ajuster(rep, q.id, 0)
}

// interroger tente une résolution, puis une seule fois de plus en cas de
// connexion morte réutilisée depuis le pool.
func (r *relais) interroger(msg []byte) ([]byte, error) {
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

func (r *relais) servirUDP(conn *net.UDPConn) {
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
			if rep := r.traiter(msg); rep != nil {
				_, _ = conn.WriteToUDP(rep, adresse)
			}
		}()
	}
}

func (r *relais) servirTCP(ecoute *net.TCPListener) {
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
func (r *relais) connexionTCP(conn net.Conn) {
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
		rep := r.traiter(msg)
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

func main() {
	log.SetFlags(log.LstdFlags)
	log.SetPrefix("tordns-client ")
	cfg := chargerConfig()
	if cfg.diagnostic {
		constats := diagnosticer(cfg.racine)
		if afficherDiagnostic(constats) > 0 {
			os.Exit(1)
		}
		return
	}
	if cfg.onion == "" {
		log.Fatal("adresse .onion requise : renseigner TORDNS_ONION ou -onion")
	}
	if _, _, err := net.SplitHostPort(cfg.ecoute); err != nil {
		log.Fatalf("adresse d'écoute invalide %q : %v", cfg.ecoute, err)
	}

	r := &relais{
		cfg:   cfg,
		cache: nouveauCache(cfg.tailleCache),
		doh:   nouveauClientDoH(cfg.onion, cfg.socks, cfg.delai, cfg.concurrence),
	}

	adresseUDP, err := net.ResolveUDPAddr("udp", cfg.ecoute)
	if err != nil {
		log.Fatalf("résolution de %s : %v", cfg.ecoute, err)
	}
	connUDP, err := net.ListenUDP("udp", adresseUDP)
	if err != nil {
		log.Fatalf("écoute UDP sur %s : %v (port < 1024 : privilège ou CAP_NET_BIND_SERVICE requis ; sinon port occupé)", cfg.ecoute, err)
	}
	adresseTCP, err := net.ResolveTCPAddr("tcp", cfg.ecoute)
	if err != nil {
		log.Fatalf("résolution de %s : %v", cfg.ecoute, err)
	}
	connTCP, err := net.ListenTCP("tcp", adresseTCP)
	if err != nil {
		connUDP.Close()
		log.Fatalf("écoute TCP sur %s : %v", cfg.ecoute, err)
	}

	fmt.Printf("TorDNS client : écoute %s (UDP/TCP), DoH via %s par SOCKS %s, cache %d entrées\n",
		cfg.ecoute, cfg.onion, cfg.socks, cfg.tailleCache)

	go r.servirUDP(connUDP)
	go r.servirTCP(connTCP)

	signaux := make(chan os.Signal, 1)
	signal.Notify(signaux, syscall.SIGINT, syscall.SIGTERM)
	<-signaux
	connUDP.Close()
	connTCP.Close()
	log.Printf("arrêt : %d requêtes, %d servies par le cache, %d erreurs",
		r.requetes.Load(), r.hits.Load(), r.erreurs.Load())
}
