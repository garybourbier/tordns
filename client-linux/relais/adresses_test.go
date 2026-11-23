package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tordns/manifeste"
)

func ecrireManifeste(t *testing.T, dossier string, adresses map[string]string, expire time.Time) string {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := manifeste.Manifeste{
		Version:  2,
		Expire:   expire.UTC().Format(time.RFC3339),
		Cibles:   map[string]manifeste.Cible{"client-linux-amd64": {URL: "http://exemple.onion/x", Taille: 1, SHA256: strings.Repeat("a", 64)}},
		Adresses: adresses,
	}
	brut, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	brut = append(brut, '\n')
	cle := hex.EncodeToString(pub)
	if err := os.MkdirAll(dossier, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dossier, "manifeste.json"), brut, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dossier, "manifeste.json.sig"), ed25519.Sign(priv, brut), 0o600); err != nil {
		t.Fatal(err)
	}
	return cle
}

func TestListeAdressesSignee(t *testing.T) {
	dossier := t.TempDir()
	coeur := strings.Repeat("c", 56) + ".onion"
	communaute := strings.Repeat("m", 56) + ".onion"
	cle := ecrireManifeste(t, dossier, map[string]string{"coeur": coeur, "communaute": communaute},
		time.Now().Add(time.Hour))
	if got := adresseEffective(dossier, cle, "coeur", "repli.onion"); got != coeur {
		t.Fatalf("cœur : %q", got)
	}
	if got := adresseEffective(dossier, cle, "secours", "repli.onion"); got != coeur {
		t.Fatalf("secours : %q", got)
	}
	if got := adresseEffective(dossier, cle, "communaute", "repli.onion"); got != communaute {
		t.Fatalf("communauté : %q", got)
	}
}

func TestListeExpireeOuFalsifieeRetombeSurLeSecours(t *testing.T) {
	dossier := t.TempDir()
	cle := ecrireManifeste(t, dossier, map[string]string{"coeur": strings.Repeat("c", 56) + ".onion"},
		time.Now().Add(-time.Hour))
	if got := adresseEffective(dossier, cle, "coeur", "repli.onion"); got != "repli.onion" {
		t.Fatalf("liste expirée : %q", got)
	}
	if err := os.WriteFile(filepath.Join(dossier, "manifeste.json"), []byte(`{"version":3}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := adresseEffective(dossier, cle, "coeur", "repli.onion"); got != "repli.onion" {
		t.Fatalf("manifeste falsifié : %q", got)
	}
}

func TestModesValides(t *testing.T) {
	for _, m := range []string{"coeur", "secours", "communaute"} {
		if !modeValide(m) {
			t.Fatalf("%s refusé", m)
		}
	}
	if modeValide("autre") {
		t.Fatal("mode inconnu accepté")
	}
}
