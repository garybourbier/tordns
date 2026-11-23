//go:build darwin

// tordns-client : relais DNS local TorDNS pour macOS.
//
// Le relais, le cache, DNSSEC et DoH sont partagés avec Linux. Ce fichier
// ajoute launchd, networksetup et le diagnostic scutil.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"tordns/client-linux/relais"
)

var version = "dev"

const (
	dossierEtat    = "/Library/Application Support/TorDNS"
	cheminEtatDNS  = dossierEtat + "/dns-original.json"
	dossierAdresse = dossierEtat + "/maj"
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
	dnssec      string
	modeAdresse string
	adresses    string
	restaurer   bool
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
		dnssec:      envOu("TORDNS_DNSSEC", "auto"),
		modeAdresse: envOu("TORDNS_MODE_ADRESSE", "coeur"),
		adresses:    envOu("TORDNS_ADRESSES", dossierAdresse),
		tailleCache: envEntier("TORDNS_CACHE", 4096),
	}
	flag.StringVar(&cfg.ecoute, "ecoute", cfg.ecoute, "adresse et port d'écoute (UDP et TCP)")
	flag.StringVar(&cfg.socks, "socks", cfg.socks, "adresse du proxy SOCKS5 de Tor")
	flag.StringVar(&cfg.onion, "onion", cfg.onion, "adresse du service caché TorDNS")
	flag.IntVar(&cfg.tailleCache, "cache", cfg.tailleCache, "nombre maximal d'entrées en cache")
	ttlMax := flag.Int("ttl-max", 3600, "durée maximale de mise en cache, en secondes")
	delai := flag.Duration("delai", 10*time.Second, "délai maximal par requête DoH")
	flag.IntVar(&cfg.concurrence, "concurrence", 64, "requêtes simultanées au maximum")
	flag.BoolVar(&cfg.diagnostic, "diagnostic", false, "inspecte les fuites DNS et quitte")
	flag.StringVar(&cfg.dnssec, "dnssec", cfg.dnssec, "validation DNSSEC : non, auto ou strict")
	flag.StringVar(&cfg.modeAdresse, "mode-adresse", cfg.modeAdresse, "adresse : coeur, secours ou communaute")
	flag.StringVar(&cfg.adresses, "adresses", cfg.adresses, "dossier du manifeste d'adresses vérifié")
	flag.BoolVar(&cfg.restaurer, "restaurer-dns", false, "restaure les DNS d'origine et quitte")
	afficherVersion := flag.Bool("version", false, "affiche la version et quitte")
	flag.Parse()
	if *afficherVersion {
		fmt.Printf("tordns-client %s\n", version)
		os.Exit(0)
	}
	cfg.ttlMax = time.Duration(*ttlMax) * time.Second
	cfg.delai = *delai
	return cfg
}

func main() {
	log.SetFlags(log.LstdFlags)
	log.SetPrefix("tordns-client ")
	cfg := chargerConfig()

	if cfg.restaurer {
		if err := restaurerDepuisEtat(cheminEtatDNS); err != nil {
			log.Fatalf("restauration DNS : %v", err)
		}
		fmt.Println("DNS d'origine restaurés.")
		return
	}
	if cfg.diagnostic {
		constats := diagnosticer()
		if afficherDiagnostic(constats) > 0 {
			os.Exit(1)
		}
		return
	}
	if !relais.ModeValide(cfg.modeAdresse) {
		log.Fatalf("mode d'adresse inconnu %q : coeur, secours ou communaute", cfg.modeAdresse)
	}
	cfg.onion = relais.AdresseEffective(cfg.adresses, relais.ClePublique(), cfg.modeAdresse, cfg.onion)
	if cfg.onion == "" {
		log.Fatal("aucune adresse .onion : renseigner TORDNS_ONION ou fournir un manifeste signé")
	}
	if _, _, err := net.SplitHostPort(cfg.ecoute); err != nil {
		log.Fatalf("adresse d'écoute invalide %q : %v", cfg.ecoute, err)
	}
	// Tor est obligatoire : jamais de repli DNS clair si le SOCKS manque.
	if err := relais.ProxyJoignable(cfg.socks, 3*time.Second); err != nil {
		log.Fatal(err)
	}
	r, err := relais.Nouveau(relais.Options{
		Onion:       cfg.onion,
		SOCKS:       cfg.socks,
		TailleCache: cfg.tailleCache,
		TTLMax:      cfg.ttlMax,
		Delai:       cfg.delai,
		Concurrence: cfg.concurrence,
		DNSSEC:      cfg.dnssec,
	})
	if err != nil {
		log.Fatal(err)
	}

	services, err := servicesReseau()
	if err != nil {
		log.Fatalf("services réseau : %v", err)
	}
	etat, err := preparerEtatDNS(cheminEtatDNS, services)
	if err != nil {
		log.Fatalf("sauvegarde des DNS : %v", err)
	}
	if err := appliquerDNS(services, []string{"127.0.0.1"}); err != nil {
		_ = restaurerDNS(etat)
		log.Fatalf("réglage DNS : %v", err)
	}
	fmt.Printf("DNS de %d service(s) réseau pointé vers 127.0.0.1 ; originaux dans %s\n", len(services), cheminEtatDNS)

	adresseUDP, err := net.ResolveUDPAddr("udp", cfg.ecoute)
	if err != nil {
		_ = restaurerDNS(etat)
		log.Fatalf("résolution de %s : %v", cfg.ecoute, err)
	}
	connUDP, err := net.ListenUDP("udp", adresseUDP)
	if err != nil {
		_ = restaurerDNS(etat)
		log.Fatalf("écoute UDP sur %s : %v (droits root requis pour le port 53)", cfg.ecoute, err)
	}
	adresseTCP, err := net.ResolveTCPAddr("tcp", cfg.ecoute)
	if err != nil {
		connUDP.Close()
		_ = restaurerDNS(etat)
		log.Fatalf("résolution de %s : %v", cfg.ecoute, err)
	}
	connTCP, err := net.ListenTCP("tcp", adresseTCP)
	if err != nil {
		connUDP.Close()
		_ = restaurerDNS(etat)
		log.Fatalf("écoute TCP sur %s : %v", cfg.ecoute, err)
	}

	fmt.Printf("TorDNS client : écoute %s (UDP/TCP), DoH via %s, cache %d entrées\n",
		cfg.ecoute, cfg.onion, cfg.tailleCache)
	go r.ServirUDP(connUDP)
	go r.ServirTCP(connTCP)

	signaux := make(chan os.Signal, 1)
	signal.Notify(signaux, syscall.SIGINT, syscall.SIGTERM)
	<-signaux
	connUDP.Close()
	connTCP.Close()
	if err := restaurerDNS(etat); err != nil {
		log.Printf("restauration DNS à l'arrêt : %v", err)
	}
	requetes, hits, erreurs := r.Stats()
	log.Printf("arrêt : %d requêtes, %d servies par le cache, %d erreurs", requetes, hits, erreurs)
}
