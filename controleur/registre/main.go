// TorDNS — service du registre communautaire (Mission 10).
//
// Écoute sur le réseau privé du contrôleur ; seul le service caché dédié le
// publie. L'état, le pool communauté et la liste des domaines restent hors
// dépôt. Aucun nom de domaine ni contact n'est journalisé.
package main

import (
	"bufio"
	"context"
	"flag"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"
)

func main() {
	etatChemin := flag.String("etat", "/donnees/registre.json", "état persistant du registre")
	poolChemin := flag.String("pool", "/pools/communaute.txt", "pool communauté à écrire")
	domainesFichier := flag.String("domaines", "", "fichier de domaines à sonder (un par ligne)")
	reference := flag.String("reference", "unbound:5335", "résolveur DNS du contrôleur (référence DNSSEC)")
	socks := flag.String("socks", "tor:9050", "proxy SOCKS pour Tor (vide : direct)")
	ecoute := flag.String("ecoute", ":8080", "adresse d'écoute HTTP")
	proxyProtocole := flag.Bool("proxy-protocole", true, "lire l'en-tête PROXY v2 de Tor (circuit)")
	hook := flag.String("hook", "", "script exécuté après chaque changement du pool")
	coeurFichier := flag.String("coeur", "", "pool cœur en lecture seule pour l'état public")
	reseauFichier := flag.String("reseau", "", "état public du réseau (JSON agrégé ; vide : non publié)")
	reseauInterne := flag.String("reseau-interne", "", "échantillons privés nécessaires aux agrégats (vide : en mémoire)")
	descripteur := flag.String("descripteur", "", "fichier dont la date de modification est la publication du descripteur")
	onionbalanceStatus := flag.String("onionbalance-status", "", "socket de statut Onionbalance (publication du descripteur)")
	quarantaine := flag.Duration("quarantaine", 72*time.Hour, "durée de quarantaine")
	intervalle := flag.Duration("intervalle", 10*time.Minute, "intervalle moyen entre deux passes")
	sondesMin := flag.Int("sondes-min", 2, "sondes réussies minimum avant admission")
	domainesParPasse := flag.Int("domaines-par-passe", 3, "domaines tirés au hasard à chaque passe")
	echecsMax := flag.Int("echecs-max", 1, "mensonges DNSSEC avant éviction")
	doutesMax := flag.Int("doutes-max", 3, "écarts non signés sur des domaines distincts avant éviction")
	indispoMax := flag.Int("indispo-max", 6, "échecs réseau consécutifs avant éviction")
	maxJour := flag.Int("max-jour", 50, "inscriptions acceptées par jour")
	maxIP := flag.Int("max-ip", 3, "inscriptions acceptées par source et par jour")
	flag.Parse()

	domaines := []string{}
	if *domainesFichier != "" {
		f, err := os.Open(*domainesFichier)
		if err != nil {
			log.Fatalf("domaines : %v", err)
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			ligne := strings.TrimSpace(sc.Text())
			if ligne == "" || strings.HasPrefix(ligne, "#") {
				continue
			}
			domaines = append(domaines, ligne)
		}
		f.Close()
		if len(domaines) == 0 {
			log.Fatal("aucun domaine à sonder")
		}
	}

	client := &http.Client{Timeout: 20 * time.Second}
	if *socks != "" {
		u, err := url.Parse("socks5://" + *socks)
		if err != nil {
			log.Fatalf("proxy SOCKS invalide : %v", err)
		}
		client.Transport = &http.Transport{Proxy: http.ProxyURL(u)}
	}

	cfg := config{
		Quarantaine:          *quarantaine,
		EchecsMax:            *echecsMax,
		DoutesMax:            *doutesMax,
		IndispoMax:           *indispoMax,
		SondesMin:            *sondesMin,
		MaxInscriptionsJour:  *maxJour,
		MaxParIP:             *maxIP,
		Reference:            *reference,
		Domaines:             domaines,
		DomainesParPasse:     *domainesParPasse,
		Client:               client,
		CoeurFichier:         *coeurFichier,
		DescripteurFichier:   *descripteur,
		OnionbalanceStatus:   *onionbalanceStatus,
		ReseauFichier:        *reseauFichier,
		ReseauInterneFichier: *reseauInterne,
	}
	r, err := nouveauRegistre(*etatChemin, *poolChemin, cfg)
	if err != nil {
		log.Fatal(err)
	}
	if *hook != "" {
		r.cfg.Hook = func() {
			// Le script ne reçoit aucun argument : tout son état vient des
			// fichiers du contrôleur, jamais de la ligne de commande.
			if err := exec.Command(*hook).Run(); err != nil {
				log.Printf("rechargement communauté : %v", err)
			}
		}
	}
	if err := r.ecrirePool(); err != nil {
		log.Fatalf("pool communauté : %v", err)
	}
	if err := r.publierReseau(time.Now()); err != nil {
		log.Printf("état réseau : %v", err)
	}

	go func() {
		for {
			// Intervalle aléatoire : les sondes ne forment pas un rythme fixe
			// exploitable pour distinguer le registre d'un client.
			attente := *intervalle/2 + time.Duration(rand.Int63n(int64(*intervalle)))
			time.Sleep(attente)
			if _, err := r.passe(); err != nil {
				log.Printf("passe de sondes : %v", err)
			}
		}
	}()

	serveur := &http.Server{
		Addr:              *ecoute,
		Handler:           r.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       30 * time.Second,
		ErrorLog:          log.New(os.Stderr, "", 0),
	}
	ecouteur, err := net.Listen("tcp", *ecoute)
	if err != nil {
		log.Fatal(err)
	}
	if *proxyProtocole {
		ecouteur = ecouteurProxy{ecouteur}
	}
	serveur.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
		if cp, ok := c.(*connProxy); ok && cp.circuit != "" {
			return context.WithValue(ctx, cleCircuit, cp.circuit)
		}
		return ctx
	}
	log.Printf("registre à l'écoute sur %s", *ecoute)
	if err := serveur.Serve(ecouteur); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
