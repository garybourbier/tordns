// tordns-client-maj — mise à jour signée du client Linux (Mission 11).
//
// Même vérification que le nœud : manifeste signé, version strictement
// supérieure, cible téléchargée par Tor avec taille et SHA-256 contrôlés.
// Le binaire est écrit à côté puis renommé (remplacement atomique) ; si le
// service ne redémarre pas, l'ancien binaire est remis en place.
package main

import (
	"crypto/sha256"
	"encoding/hex"
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
	"time"

	"tordns/manifeste"
)

type Etat struct {
	Version int64  `json:"version"`
	Cle     string `json:"cle,omitempty"`
	// Rejetee retient la dernière version dont le binaire a été refusé par le
	// service : le minuteur ne doit pas réinstaller la même version cassée.
	Rejetee int64 `json:"rejetee,omitempty"`
}

type Config struct {
	ManifesteURL   string
	SignatureURL   string
	SOCKS          string
	Cible          string
	Binaire        string
	Service        string
	Systemctl      string
	Etat           string
	CacheManifeste string
	CacheSignature string
	Cle            string
	Delai          time.Duration
	Maintenant     func() time.Time
}

type maj struct {
	cfg     Config
	client  *http.Client
	execCmd func(nom string, args ...string) error
	log     io.Writer
}

func main() {
	cfg := Config{
		ManifesteURL:   envOu("TORDNS_MAJ_MANIFESTE", ""),
		SignatureURL:   envOu("TORDNS_MAJ_SIGNATURE", ""),
		SOCKS:          envOu("TORDNS_MAJ_SOCKS", "127.0.0.1:9050"),
		Cible:          envOu("TORDNS_MAJ_CIBLE", "client-linux-amd64"),
		Binaire:        envOu("TORDNS_MAJ_BINAIRE", "/usr/local/bin/tordns-client"),
		Service:        envOu("TORDNS_MAJ_SERVICE", "tordns-client"),
		Systemctl:      envOu("TORDNS_MAJ_SYSTEMCTL", "systemctl"),
		Etat:           envOu("TORDNS_MAJ_ETAT", "/var/lib/tordns/maj-client.json"),
		CacheManifeste: envOu("TORDNS_MAJ_ADRESSES", "/var/lib/tordns/maj/manifeste.json"),
		Cle:            envOu("TORDNS_MAJ_CLE", manifeste.ClePubliqueEpinglee),
		Delai:          2 * time.Minute,
		Maintenant:     time.Now,
	}
	flag.StringVar(&cfg.ManifesteURL, "manifeste", cfg.ManifesteURL, "URL du manifeste")
	flag.StringVar(&cfg.SignatureURL, "signature", cfg.SignatureURL, "URL de la signature")
	flag.StringVar(&cfg.SOCKS, "socks", cfg.SOCKS, "proxy SOCKS5 de Tor (vide : direct, tests)")
	flag.StringVar(&cfg.Cible, "cible", cfg.Cible, "nom de la cible dans le manifeste")
	flag.StringVar(&cfg.Binaire, "binaire", cfg.Binaire, "binaire installé à remplacer")
	flag.StringVar(&cfg.Service, "service", cfg.Service, "unité systemd à redémarrer")
	flag.StringVar(&cfg.Systemctl, "systemctl", cfg.Systemctl, "commande systemctl (tests)")
	flag.StringVar(&cfg.Etat, "etat", cfg.Etat, "fichier d'état")
	flag.StringVar(&cfg.CacheManifeste, "cache-manifeste", cfg.CacheManifeste, "manifeste vérifié conservé pour la liste d'adresses")
	flag.StringVar(&cfg.Cle, "cle", cfg.Cle, "clé publique de publication (tests/rotation)")
	flag.Parse()
	cfg.CacheSignature = cfg.CacheManifeste + ".sig"

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
	u := &maj{cfg: cfg, client: client, execCmd: executer, log: os.Stdout}
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

func nouveauClient(socks string, delai time.Duration) (*http.Client, error) {
	transport := &http.Transport{
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

func executer(nom string, args ...string) error {
	cmd := exec.Command(nom, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func (u *maj) executer() error {
	etat, err := lireEtat(u.cfg.Etat)
	if err != nil {
		return fmt.Errorf("état illisible : %w", err)
	}
	brut, sig, err := u.telecharger(u.cfg.ManifesteURL, u.cfg.SignatureURL)
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
		return fmt.Errorf("v%d déjà rejetée par le service : pas de nouvelle tentative", m.Version)
	}
	cible, ok := m.Cibles[u.cfg.Cible]
	if !ok {
		return fmt.Errorf("cible %q absente du manifeste", u.cfg.Cible)
	}

	nouveau, err := u.get(cible.URL, cible.Taille)
	if err != nil {
		return fmt.Errorf("téléchargement de %s : %w", cible.URL, err)
	}
	if int64(len(nouveau)) != cible.Taille {
		return fmt.Errorf("taille de %s : %d octets, attendu %d", u.cfg.Cible, len(nouveau), cible.Taille)
	}
	somme := sha256.Sum256(nouveau)
	if hex.EncodeToString(somme[:]) != cible.SHA256 {
		return fmt.Errorf("SHA-256 de %s différent du manifeste", u.cfg.Cible)
	}

	if err := u.remplacer(nouveau); err != nil {
		return err
	}
	if err := u.redemarrer(); err != nil {
		fmt.Printf("Le service ne redémarre pas (%v) : retour au binaire précédent.\n", err)
		if errAr := u.restaurer(); errAr != nil {
			return fmt.Errorf("retour arrière impossible : %w (service : %v)", errAr, err)
		}
		if errAr := u.redemarrer(); errAr != nil {
			return fmt.Errorf("l'ancien binaire ne redémarre pas non plus : %w", errAr)
		}
		// Retenir le rejet avant de rendre la main : au prochain passage du
		// minuteur, la même version ne doit pas couper le service à nouveau.
		if errAr := ecrireEtat(u.cfg.Etat, Etat{Version: etat.Version, Cle: etat.Cle, Rejetee: m.Version}); errAr != nil {
			return fmt.Errorf("v%d rejetée, version précédente rétablie, mais état non écrit : %w", m.Version, errAr)
		}
		return fmt.Errorf("v%d rejetée par le service, version précédente rétablie", m.Version)
	}

	if u.cfg.CacheManifeste != "" {
		// Données publiques signées : lisibles par le service tordns, non
		// modifiables par lui.
		if err := os.MkdirAll(filepath.Dir(u.cfg.CacheManifeste), 0o755); err != nil {
			return fmt.Errorf("dossier du manifeste : %w", err)
		}
		if err := os.WriteFile(u.cfg.CacheManifeste, brut, 0o644); err != nil {
			return fmt.Errorf("cache du manifeste : %w", err)
		}
		if err := os.WriteFile(u.cfg.CacheSignature, sig, 0o644); err != nil {
			return fmt.Errorf("cache de la signature : %w", err)
		}
	}
	nouvel := Etat{Version: m.Version, Cle: etat.Cle}
	if m.CleSuivante != "" {
		nouvel.Cle = m.CleSuivante
	}
	if err := ecrireEtat(u.cfg.Etat, nouvel); err != nil {
		return fmt.Errorf("mise à jour appliquée mais état non écrit : %w", err)
	}
	fmt.Printf("Client mis à jour en v%d.\n", m.Version)
	return nil
}

func (u *maj) telecharger(manifesteURL, signatureURL string) ([]byte, []byte, error) {
	brut, err := u.get(manifesteURL, manifeste.TailleMaxManifeste)
	if err != nil {
		return nil, nil, fmt.Errorf("manifeste : %w", err)
	}
	sig, err := u.get(signatureURL, 4096)
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

// remplacer écrit le nouveau binaire dans le même dossier (même système de
// fichiers), le rend exécutable, conserve l'ancien puis renomme atomiquement.
func (u *maj) remplacer(nouveau []byte) error {
	dossier := filepath.Dir(u.cfg.Binaire)
	tmp, err := os.CreateTemp(dossier, ".tordns-client.*")
	if err != nil {
		return err
	}
	cheminTmp := tmp.Name()
	defer os.Remove(cheminTmp)
	if _, err := tmp.Write(nouveau); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(cheminTmp, 0o755); err != nil {
		return err
	}
	if _, err := os.Stat(u.cfg.Binaire); err == nil {
		if err := os.Rename(u.cfg.Binaire, u.cfg.Binaire+".precedent"); err != nil {
			return err
		}
	}
	return os.Rename(cheminTmp, u.cfg.Binaire)
}

func (u *maj) restaurer() error {
	if _, err := os.Stat(u.cfg.Binaire + ".precedent"); err != nil {
		return err
	}
	return os.Rename(u.cfg.Binaire+".precedent", u.cfg.Binaire)
}

func (u *maj) redemarrer() error {
	if err := u.execCmd(u.cfg.Systemctl, "restart", u.cfg.Service); err != nil {
		return err
	}
	// Laisse à systemd le temps de constater un démarrage immédiat.
	time.Sleep(500 * time.Millisecond)
	return u.execCmd(u.cfg.Systemctl, "is-active", "--quiet", u.cfg.Service)
}

func lireEtat(chemin string) (Etat, error) {
	var etat Etat
	brut, err := os.ReadFile(chemin)
	if errors.Is(err, os.ErrNotExist) {
		return etat, nil
	}
	if err != nil {
		return etat, err
	}
	return etat, json.Unmarshal(brut, &etat)
}

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
