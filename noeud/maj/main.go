// tordns-maj — mise à jour signée d'un nœud TorDNS (Mission 11).
//
// Récupère manifeste.json et sa signature par Tor (SOCKS5), vérifie la
// signature et la version, tire les images Docker par empreinte (jamais par
// étiquette), relance la stack puis sonde la santé. Si la sonde échoue ou si
// la stack ne repart pas, la version précédente est rétablie.
//
// Aucune donnée de requête DNS n'est lue ni journalisée : seuls la version,
// les empreintes d'images et les erreurs de mise à jour sont écrites.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"tordns/manifeste"
)

// Etat est conservé entre deux exécutions : version appliquée, images par
// empreinte, et clé de confiance (rotation annoncée par un manifeste signé).
type Etat struct {
	Version int64             `json:"version"`
	Images  map[string]string `json:"images"`
	Cle     string            `json:"cle,omitempty"`
	// Rejetee retient la dernière version dont la sonde de santé a échoué :
	// le minuteur ne doit pas réappliquer la même version cassée.
	Rejetee int64 `json:"rejetee,omitempty"`
}

// Config rassemble les chemins et l'horloge, injectables dans les tests.
type Config struct {
	ManifesteURL   string
	SignatureURL   string
	SOCKS          string
	Etat           string
	ComposeDir     string
	ComposeFichier string
	EnvFichier     string
	Sante          string
	Cle            string
	Delai          time.Duration
	Maintenant     func() time.Time
}

type maj struct {
	cfg    Config
	client *http.Client
	docker func(args ...string) error
	log    io.Writer
}

func main() {
	cfg := Config{
		ManifesteURL:   envOu("TORDNS_MAJ_MANIFESTE", ""),
		SignatureURL:   envOu("TORDNS_MAJ_SIGNATURE", ""),
		SOCKS:          envOu("TORDNS_MAJ_SOCKS", ""),
		Etat:           envOu("TORDNS_MAJ_ETAT", "/var/lib/tordns/maj-etat.json"),
		ComposeDir:     envOu("TORDNS_MAJ_COMPOSE", "/opt/tordns/noeud"),
		ComposeFichier: envOu("TORDNS_MAJ_COMPOSE_FICHIER", "docker-compose.yml"),
		EnvFichier:     envOu("TORDNS_MAJ_ENV", "/opt/tordns/.env"),
		Sante:          envOu("TORDNS_MAJ_SANTE", ""),
		Cle:            envOu("TORDNS_MAJ_CLE", manifeste.ClePubliqueEpinglee),
		Delai:          2 * time.Minute,
		Maintenant:     time.Now,
	}
	flag.StringVar(&cfg.ManifesteURL, "manifeste", cfg.ManifesteURL, "URL du manifeste")
	flag.StringVar(&cfg.SignatureURL, "signature", cfg.SignatureURL, "URL de la signature (défaut : manifeste + .sig)")
	flag.StringVar(&cfg.SOCKS, "socks", cfg.SOCKS, "proxy SOCKS5 de Tor (vide : direct, réservé aux tests)")
	flag.StringVar(&cfg.Etat, "etat", cfg.Etat, "fichier d'état")
	flag.StringVar(&cfg.ComposeDir, "compose", cfg.ComposeDir, "dossier du docker-compose.yml du nœud")
	flag.StringVar(&cfg.EnvFichier, "env", cfg.EnvFichier, "fichier .env de compose")
	flag.StringVar(&cfg.Sante, "sante", cfg.Sante, "URL de santé sondée après relance")
	flag.StringVar(&cfg.Cle, "cle", cfg.Cle, "clé publique de publication (tests/rotation)")
	flag.Parse()

	if cfg.ManifesteURL == "" {
		fmt.Fprintln(os.Stderr, "ERREUR : aucune URL de manifeste (TORDNS_MAJ_MANIFESTE ou -manifeste)")
		os.Exit(1)
	}
	if cfg.SignatureURL == "" {
		cfg.SignatureURL = cfg.ManifesteURL + ".sig"
	}

	client, err := nouveauClient(cfg.SOCKS, cfg.Delai)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERREUR : %v\n", err)
		os.Exit(1)
	}
	u := &maj{cfg: cfg, client: client, docker: dockerCompose(cfg), log: os.Stdout}
	if err := u.executer(); err != nil {
		fmt.Fprintf(os.Stderr, "MISE À JOUR REFUSÉE : %v\n", err)
		os.Exit(1)
	}
}

func envOu(cle, defaut string) string {
	if v := os.Getenv(cle); v != "" {
		return v
	}
	return defaut
}

// nouveauClient construit un client HTTP qui passe par Tor quand un proxy
// SOCKS5 est configuré. Le transport de Go parle socks5 nativement.
func nouveauClient(socks string, delai time.Duration) (*http.Client, error) {
	transport := &http.Transport{
		Proxy:                 nil,
		ResponseHeaderTimeout: 45 * time.Second,
		DisableKeepAlives:     true,
	}
	if socks != "" {
		u, err := url.Parse("socks5://" + socks)
		if err != nil {
			return nil, fmt.Errorf("proxy SOCKS invalide %q : %w", socks, err)
		}
		transport.Proxy = http.ProxyURL(u)
	}
	return &http.Client{Transport: transport, Timeout: delai}, nil
}

func dockerCompose(cfg Config) func(args ...string) error {
	return func(args ...string) error {
		base := []string{"compose", "--env-file", cfg.EnvFichier, "-f", cfg.ComposeFichier}
		cmd := exec.Command("docker", append(base, args...)...)
		cmd.Dir = cfg.ComposeDir
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	}
}

func (u *maj) executer() error {
	etat, err := lireEtat(u.cfg.Etat)
	if err != nil {
		return fmt.Errorf("état illisible : %w", err)
	}
	brut, sig, err := u.telecharger()
	if err != nil {
		return err
	}
	cle := u.cfg.Cle
	if etat.Cle != "" {
		cle = etat.Cle
	}
	m, err := manifeste.Accepter(brut, sig, cle, etat.Version, u.cfg.Maintenant())
	if err != nil {
		return err
	}
	if m.Version == etat.Rejetee {
		return fmt.Errorf("v%d déjà rejetée par la sonde : pas de nouvelle tentative", m.Version)
	}
	if len(m.Images) == 0 {
		return errors.New("manifeste sans image de nœud : rien à appliquer")
	}
	if len(etat.Images) == 0 {
		return errors.New("aucune version précédente connue : retour arrière impossible, mise à jour refusée")
	}

	fmt.Printf("Manifeste v%d accepté (version installée %d).\n", m.Version, etat.Version)
	if err := u.appliquer(m.Images); err != nil {
		return fmt.Errorf("application de la v%d : %w", m.Version, err)
	}
	if err := u.sonder(); err != nil {
		fmt.Printf("Sonde de santé en échec (%v) : retour à la v%d.\n", err, etat.Version)
		if errAr := u.appliquer(etat.Images); errAr != nil {
			return fmt.Errorf("retour arrière impossible : %w (santé : %v)", errAr, err)
		}
		if errAr := u.sonder(); errAr != nil {
			return fmt.Errorf("la version précédente ne répond pas non plus : %w", errAr)
		}
		// Retenir le rejet avant de rendre la main : la même version cassée ne
		// doit pas être réappliquée au prochain passage du minuteur.
		rejet := etat
		rejet.Rejetee = m.Version
		if errAr := ecrireEtat(u.cfg.Etat, rejet); errAr != nil {
			return fmt.Errorf("v%d rejetée, v%d rétablie, mais état non écrit : %w", m.Version, etat.Version, errAr)
		}
		return fmt.Errorf("v%d rejetée par la sonde, v%d rétablie", m.Version, etat.Version)
	}

	nouvel := Etat{Version: m.Version, Images: m.Images, Cle: etat.Cle}
	if m.CleSuivante != "" {
		nouvel.Cle = m.CleSuivante
		fmt.Printf("Rotation de clé annoncée : %s…\n", m.CleSuivante[:16])
	}
	if err := ecrireEtat(u.cfg.Etat, nouvel); err != nil {
		return fmt.Errorf("mise à jour appliquée mais état non écrit : %w", err)
	}
	fmt.Printf("Nœud mis à jour en v%d.\n", m.Version)
	return nil
}

// telecharger récupère manifeste et signature, avec une taille bornée.
func (u *maj) telecharger() ([]byte, []byte, error) {
	brut, err := u.get(u.cfg.ManifesteURL, manifeste.TailleMaxManifeste)
	if err != nil {
		return nil, nil, fmt.Errorf("manifeste : %w", err)
	}
	sig, err := u.get(u.cfg.SignatureURL, 4096)
	if err != nil {
		return nil, nil, fmt.Errorf("signature : %w", err)
	}
	return brut, sig, nil
}

func (u *maj) get(adresse string, max int64) ([]byte, error) {
	rep, err := u.client.Get(adresse)
	if err != nil {
		return nil, err
	}
	defer rep.Body.Close()
	if rep.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", rep.StatusCode)
	}
	return io.ReadAll(io.LimitReader(rep.Body, max+1))
}

// appliquer écrit un fichier override qui fixe chaque image par empreinte,
// puis tire et relance. Aucune étiquette n'entre dans compose.
func (u *maj) appliquer(images map[string]string) error {
	var b strings.Builder
	b.WriteString("# TorDNS — images fixées par empreinte, écrit par tordns-maj.\n")
	b.WriteString("services:\n")
	for service, ref := range images {
		// Le manifeste porte déjà « nom@sha256:… » ; aucune étiquette locale
		// n'est consultée, donc aucune ne peut être substituée.
		if !strings.Contains(ref, "@sha256:") {
			return fmt.Errorf("image %q non épinglée : %q", service, ref)
		}
		fmt.Fprintf(&b, "  %s:\n    image: %s\n", service, ref)
	}
	override := filepath.Join(u.cfg.ComposeDir, "maj-images.yml")
	if err := os.WriteFile(override, []byte(b.String()), 0o600); err != nil {
		return err
	}
	if err := u.docker("pull", "--quiet"); err != nil {
		return fmt.Errorf("docker compose pull : %w", err)
	}
	return u.docker("up", "-d", "--remove-orphans")
}

// sonder attend que la santé réponde 200 ; sans URL configurée, seule la
// relance compte (la sonde est alors réputée réussie).
func (u *maj) sonder() error {
	if u.cfg.Sante == "" {
		return nil
	}
	var derniere error
	for i := 0; i < 15; i++ {
		rep, err := u.client.Get(u.cfg.Sante)
		if err == nil {
			io.Copy(io.Discard, io.LimitReader(rep.Body, 4096))
			rep.Body.Close()
			if rep.StatusCode == http.StatusOK {
				return nil
			}
			derniere = fmt.Errorf("HTTP %d", rep.StatusCode)
		} else {
			derniere = err
		}
		time.Sleep(2 * time.Second)
	}
	return derniere
}

func lireEtat(chemin string) (Etat, error) {
	etat := Etat{Images: map[string]string{}}
	brut, err := os.ReadFile(chemin)
	if errors.Is(err, os.ErrNotExist) {
		return etat, nil
	}
	if err != nil {
		return etat, err
	}
	if err := json.Unmarshal(brut, &etat); err != nil {
		return etat, err
	}
	if etat.Images == nil {
		etat.Images = map[string]string{}
	}
	return etat, nil
}

// ecrireEtat remplace l'état atomiquement (écriture voisine puis rename).
func ecrireEtat(chemin string, etat Etat) error {
	brut, err := json.MarshalIndent(etat, "", "  ")
	if err != nil {
		return err
	}
	brut = append(brut, '\n')
	if err := os.MkdirAll(filepath.Dir(chemin), 0o700); err != nil {
		return err
	}
	tmp := chemin + ".tmp"
	if err := os.WriteFile(tmp, brut, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, chemin)
}
