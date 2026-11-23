package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tordns/manifeste"
)

func manifesteClient(t *testing.T, priv ed25519.PrivateKey, version int64, binaire []byte, expire time.Time, url string) ([]byte, []byte) {
	t.Helper()
	somme := sha256.Sum256(binaire)
	m := manifeste.Manifeste{
		Version: version,
		Expire:  expire.UTC().Format(time.RFC3339),
		Cibles: map[string]manifeste.Cible{
			"client-linux-amd64": {
				URL:    url,
				Taille: int64(len(binaire)),
				SHA256: hex.EncodeToString(somme[:]),
			},
		},
	}
	brut, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return brut, ed25519.Sign(priv, brut)
}

type banc struct {
	cfg      Config
	manifest []byte
	sig      []byte
	binaire  string
	appels   []string
}

func nouveauBanc(t *testing.T, version int64, contenu []byte, expire time.Time) *banc {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dossier := t.TempDir()
	b := &banc{binaire: filepath.Join(dossier, "tordns-client")}
	if err := os.WriteFile(b.binaire, []byte("v1"), 0o755); err != nil {
		t.Fatal(err)
	}
	serveur := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".sig") {
			w.Write(b.sig)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/tordns-client") {
			w.Write(contenu)
			return
		}
		w.Write(b.manifest)
	}))
	t.Cleanup(serveur.Close)
	b.manifest, b.sig = manifesteClient(t, priv, version, contenu, expire,
		serveur.URL+"/tordns-client")
	b.cfg = Config{
		ManifesteURL: serveur.URL + "/manifeste.json",
		SignatureURL: serveur.URL + "/manifeste.json.sig",
		Cible:        "client-linux-amd64",
		Binaire:      b.binaire,
		Service:      "tordns-client",
		Systemctl:    "systemctl-factice",
		Etat:         filepath.Join(dossier, "etat.json"),
		Cle:          hex.EncodeToString(pub),
		Delai:        5 * time.Second,
		Maintenant:   time.Now,
	}
	return b
}

func (b *banc) updater(client *http.Client, systemctl func(string, ...string) error) *maj {
	return &maj{cfg: b.cfg, client: client, log: os.Stdout, execCmd: systemctl}
}

func clientDirect(t *testing.T, b *banc) *http.Client {
	t.Helper()
	c, err := nouveauClient("", b.cfg.Delai)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestClientPasseEnV2(t *testing.T) {
	v2 := []byte("binaire v2")
	b := nouveauBanc(t, 2, v2, time.Now().Add(24*time.Hour))
	ok := func(nom string, args ...string) error { return nil }
	if err := b.updater(clientDirect(t, b), ok).executer(); err != nil {
		t.Fatalf("v2 refusée : %v", err)
	}
	lu, _ := os.ReadFile(b.binaire)
	if string(lu) != "binaire v2" {
		t.Fatalf("binaire non remplacé : %q", lu)
	}
	etat, _ := lireEtat(b.cfg.Etat)
	if etat.Version != 2 {
		t.Fatalf("état non mis à jour : %+v", etat)
	}
}

func TestClientRejeuRefuse(t *testing.T) {
	v2 := []byte("binaire v2")
	b := nouveauBanc(t, 1, v2, time.Now().Add(24*time.Hour))
	ecrireEtat(b.cfg.Etat, Etat{Version: 2})
	if err := b.updater(clientDirect(t, b), func(string, ...string) error { return nil }).executer(); err == nil {
		t.Fatal("v1 rejouée acceptée")
	}
	lu, _ := os.ReadFile(b.binaire)
	if string(lu) != "v1" {
		t.Fatal("binaire modifié malgré le refus")
	}
}

func TestClientSystemdEchoueRetourArriere(t *testing.T) {
	v2 := []byte("binaire v2")
	b := nouveauBanc(t, 2, v2, time.Now().Add(24*time.Hour))
	appels := 0
	faux := func(nom string, args ...string) error {
		appels++
		// Le premier redémarrage échoue, celui de la restauration réussit.
		if appels == 1 {
			return fmt.Errorf("service mort")
		}
		return nil
	}
	if err := b.updater(clientDirect(t, b), faux).executer(); err == nil {
		t.Fatal("échec systemd ignoré")
	}
	lu, _ := os.ReadFile(b.binaire)
	if string(lu) != "v1" {
		t.Fatalf("binaire non restauré : %q", lu)
	}
	etat, _ := lireEtat(b.cfg.Etat)
	if etat.Version != 0 {
		t.Fatalf("état avancé malgré l'échec : %+v", etat)
	}
	if etat.Rejetee != 2 {
		t.Fatalf("version rejetée non retenue : %+v", etat)
	}
	// Second passage du minuteur : la même v2 ne doit pas être retentée.
	appels = 0
	err := b.updater(clientDirect(t, b), faux).executer()
	if err == nil || !strings.Contains(err.Error(), "déjà rejetée") {
		t.Fatalf("v2 cassée retentée : %v", err)
	}
	if appels != 0 {
		t.Fatalf("service redémarré pour une version rejetée : %d appels", appels)
	}
}

func TestClientVersionRejeteePuisV3(t *testing.T) {
	v3 := []byte("binaire v3")
	b := nouveauBanc(t, 3, v3, time.Now().Add(24*time.Hour))
	if err := ecrireEtat(b.cfg.Etat, Etat{Version: 1, Rejetee: 2}); err != nil {
		t.Fatal(err)
	}
	if err := b.updater(clientDirect(t, b), func(string, ...string) error { return nil }).executer(); err != nil {
		t.Fatalf("v3 refusée après rejet de v2 : %v", err)
	}
	etat, _ := lireEtat(b.cfg.Etat)
	if etat.Version != 3 || etat.Rejetee != 0 {
		t.Fatalf("état v3 incorrect : %+v", etat)
	}
	lu, _ := os.ReadFile(b.binaire)
	if string(lu) != "binaire v3" {
		t.Fatalf("binaire v3 non installé : %q", lu)
	}
}

func TestClientManifesteAltereRefuse(t *testing.T) {
	b := nouveauBanc(t, 2, []byte("binaire v2"), time.Now().Add(24*time.Hour))
	b.manifest[5] ^= 0x01
	if err := b.updater(clientDirect(t, b), func(string, ...string) error { return nil }).executer(); err == nil {
		t.Fatal("manifeste altéré accepté")
	}
}

func TestClientExpireRefuse(t *testing.T) {
	b := nouveauBanc(t, 2, []byte("binaire v2"), time.Now().Add(-time.Hour))
	if err := b.updater(clientDirect(t, b), func(string, ...string) error { return nil }).executer(); err == nil {
		t.Fatal("manifeste expiré accepté")
	}
}
