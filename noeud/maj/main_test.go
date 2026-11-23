package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tordns/manifeste"
)

const (
	digestV1 = "sha256:" + "1111111111111111111111111111111111111111111111111111111111111111"
	digestV2 = "sha256:" + "2222222222222222222222222222222222222222222222222222222222222222"
	imageV1  = "ghcr.io/tordns/unbound@" + digestV1
	imageV2  = "ghcr.io/tordns/unbound@" + digestV2
	digestV3 = "sha256:" + "3333333333333333333333333333333333333333333333333333333333333333"
	imageV3  = "ghcr.io/tordns/unbound@" + digestV3
)

func manifesteSigne(t *testing.T, priv ed25519.PrivateKey, version int64, image string) ([]byte, []byte) {
	t.Helper()
	m := manifeste.Manifeste{
		Version: version,
		Expire:  time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339),
		Cibles: map[string]manifeste.Cible{
			"client-linux-amd64": {
				URL:    "http://exemple.invalid/tordns-client",
				Taille: 10,
				SHA256: strings.Repeat("aa", 32),
			},
		},
		Images: map[string]string{"unbound": image},
	}
	brut, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return brut, ed25519.Sign(priv, brut)
}

func preparer(t *testing.T, publie func(http.ResponseWriter, *http.Request)) (Config, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serveur := httptest.NewServer(http.HandlerFunc(publie))
	t.Cleanup(serveur.Close)
	dossier := t.TempDir()
	cfg := Config{
		ManifesteURL: serveur.URL + "/manifeste.json",
		SignatureURL: serveur.URL + "/manifeste.json.sig",
		Etat:         filepath.Join(dossier, "etat.json"),
		ComposeDir:   dossier,
		EnvFichier:   filepath.Join(dossier, ".env"),
		Cle:          hex.EncodeToString(pub),
		Delai:        5 * time.Second,
		Maintenant:   time.Now,
	}
	return cfg, pub, priv
}

func etatInitial(t *testing.T, cfg Config) {
	t.Helper()
	os.WriteFile(cfg.EnvFichier, nil, 0o600)
	if err := ecrireEtat(cfg.Etat, Etat{
		Version: 1,
		Images:  map[string]string{"unbound": imageV1},
	}); err != nil {
		t.Fatal(err)
	}
}

func TestAppliqueV2(t *testing.T) {
	var manifesteJSON, signature []byte
	cfg, _, priv := preparer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".sig") {
			w.Write(signature)
			return
		}
		w.Write(manifesteJSON)
	})
	manifesteJSON, signature = manifesteSigne(t, priv, 2, imageV2)
	etatInitial(t, cfg)
	cfg.Sante = "http://sante.invalid/healthz"

	var appels []string
	u := &maj{cfg: cfg, client: cfgClient(t, cfg), log: os.Stdout, docker: func(args ...string) error {
		appels = append(appels, strings.Join(args, " "))
		return nil
	}}
	// La sonde passe toujours : on remplace le client par un serveur local.
	sante := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer sante.Close()
	u.cfg.Sante = sante.URL
	if err := u.executer(); err != nil {
		t.Fatalf("v2 refusée : %v", err)
	}
	etat, err := lireEtat(cfg.Etat)
	if err != nil || etat.Version != 2 || etat.Images["unbound"] != imageV2 {
		t.Fatalf("état non mis à jour : %+v (%v)", etat, err)
	}
	if len(appels) < 2 || appels[0] != "pull --quiet" || !strings.Contains(appels[1], "up -d") {
		t.Fatalf("commandes docker inattendues : %v", appels)
	}
	override, err := os.ReadFile(filepath.Join(cfg.ComposeDir, "maj-images.yml"))
	if err != nil || !strings.Contains(string(override), imageV2) {
		t.Fatalf("override sans empreinte v2 : %s (%v)", override, err)
	}
}

func TestRejeuV1Refuse(t *testing.T) {
	// L'état dit v2 : un manifeste v1, même signé, ne doit rien changer.
	cfg, _, priv := preparer(t, http.NotFound)
	etatInitial(t, cfg)
	if err := ecrireEtat(cfg.Etat, Etat{Version: 2, Images: map[string]string{"unbound": imageV2}}); err != nil {
		t.Fatal(err)
	}
	brut, signature := manifesteSigne(t, priv, 1, imageV1)
	if _, err := manifeste.Accepter(brut, signature, cfg.Cle, 2, time.Now()); err == nil {
		t.Fatal("manifeste v1 accepté au-dessus de v2")
	}
	if err := appliquerManifeste(t, cfg, brut, signature); err == nil {
		t.Fatal("rejeu v1 appliqué")
	}
}

// appliquerManifeste sert un manifeste local et lance l'updater sans sonde.
func appliquerManifeste(t *testing.T, cfg Config, brut, signature []byte) error {
	t.Helper()
	serveur := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".sig") {
			w.Write(signature)
			return
		}
		w.Write(brut)
	}))
	defer serveur.Close()
	cfg.ManifesteURL = serveur.URL + "/manifeste.json"
	cfg.SignatureURL = serveur.URL + "/manifeste.json.sig"
	u := &maj{cfg: cfg, client: cfgClient(t, cfg), log: os.Stdout, docker: func(args ...string) error { return nil }}
	return u.executer()
}

func TestManifesteAltereRefuse(t *testing.T) {
	cfg, _, priv := preparer(t, http.NotFound)
	etatInitial(t, cfg)
	brut, signature := manifesteSigne(t, priv, 2, imageV2)
	altere := append([]byte(nil), brut...)
	altere[len(altere)/2] ^= 0x01
	if err := appliquerManifeste(t, cfg, altere, signature); err == nil {
		t.Fatal("manifeste altéré appliqué")
	}
	etat, _ := lireEtat(cfg.Etat)
	if etat.Version != 1 {
		t.Fatalf("état modifié malgré le refus : %+v", etat)
	}
}

func TestImageCasseeRetourArriere(t *testing.T) {
	cfg, _, priv := preparer(t, http.NotFound)
	etatInitial(t, cfg)

	// current reflète ce que docker vient d'appliquer ; la santé échoue sur v2.
	current := imageV1
	appels := 0
	u := &maj{cfg: cfg, log: os.Stdout, docker: func(args ...string) error {
		appels++
		if len(args) > 0 && args[0] == "up" {
			override, err := os.ReadFile(filepath.Join(cfg.ComposeDir, "maj-images.yml"))
			if err != nil {
				return err
			}
			if strings.Contains(string(override), imageV2) {
				current = imageV2
			} else {
				current = imageV1
			}
		}
		return nil
	}}
	sante := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if current == imageV1 {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer sante.Close()
	cfg.Sante = sante.URL

	brut, signature := manifesteSigne(t, priv, 2, imageV2)
	serveur := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".sig") {
			w.Write(signature)
			return
		}
		w.Write(brut)
	}))
	defer serveur.Close()
	cfg.ManifesteURL = serveur.URL + "/manifeste.json"
	cfg.SignatureURL = serveur.URL + "/manifeste.json.sig"
	u.cfg = cfg
	u.client = cfgClient(t, cfg)

	if err := u.executer(); err == nil {
		t.Fatal("image cassée acceptée")
	}
	if current != imageV1 {
		t.Fatalf("retour arrière non effectué : %s", current)
	}
	etat, _ := lireEtat(cfg.Etat)
	if etat.Version != 1 || etat.Rejetee != 2 {
		t.Fatalf("état incorrect après retour arrière : %+v", etat)
	}
	// Second passage du minuteur : la v2 rejetée ne doit pas être réappliquée.
	appels = 0
	if err := u.executer(); err == nil || !strings.Contains(err.Error(), "déjà rejetée") {
		t.Fatalf("v2 cassée retentée : %v", err)
	}
	if appels != 0 {
		t.Fatalf("docker relancé pour une version rejetée : %d appels", appels)
	}
}

func TestVersionRejeteePuisV3(t *testing.T) {
	cfg, _, priv := preparer(t, http.NotFound)
	etatInitial(t, cfg)
	if err := ecrireEtat(cfg.Etat, Etat{
		Version: 1,
		Images:  map[string]string{"unbound": imageV1},
		Rejetee: 2,
	}); err != nil {
		t.Fatal(err)
	}
	current := imageV1
	u := &maj{cfg: cfg, log: os.Stdout, docker: func(args ...string) error {
		if len(args) > 0 && args[0] == "up" {
			override, err := os.ReadFile(filepath.Join(cfg.ComposeDir, "maj-images.yml"))
			if err != nil {
				return err
			}
			if strings.Contains(string(override), imageV3) {
				current = imageV3
			} else {
				current = imageV1
			}
		}
		return nil
	}}
	sante := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if current == imageV3 {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer sante.Close()
	cfg.Sante = sante.URL
	brut, signature := manifesteSigne(t, priv, 3, imageV3)
	serveur := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".sig") {
			w.Write(signature)
			return
		}
		w.Write(brut)
	}))
	defer serveur.Close()
	cfg.ManifesteURL = serveur.URL + "/manifeste.json"
	cfg.SignatureURL = serveur.URL + "/manifeste.json.sig"
	u.cfg = cfg
	u.client = cfgClient(t, cfg)

	if err := u.executer(); err != nil {
		t.Fatalf("v3 refusée après rejet de v2 : %v", err)
	}
	etat, _ := lireEtat(cfg.Etat)
	if etat.Version != 3 || etat.Images["unbound"] != imageV3 || etat.Rejetee != 0 {
		t.Fatalf("état v3 incorrect : %+v", etat)
	}
}

// cfgClient construit un client direct (les tests n'ont pas de Tor).
func cfgClient(t *testing.T, cfg Config) *http.Client {
	t.Helper()
	c, err := nouveauClient("", cfg.Delai)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
