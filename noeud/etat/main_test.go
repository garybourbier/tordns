// Tests de la page d'état : classification de charge et lecture du port de
// contrôle Tor. Aucun réseau réel, aucun conteneur.
package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestClasserCharge(t *testing.T) {
	cas := []struct {
		moyenne float64
		attendu string
	}{
		{0, "faible"},
		{0.99, "faible"},
		{1, "moyenne"},
		{2.9, "moyenne"},
		{3, "forte"},
		{42, "forte"},
	}
	for _, c := range cas {
		if got := classerCharge(c.moyenne); got != c.attendu {
			t.Errorf("classerCharge(%v) = %q, attendu %q", c.moyenne, got, c.attendu)
		}
	}
}

func TestLireCharge(t *testing.T) {
	dir := t.TempDir()
	chemin := filepath.Join(dir, "loadavg")
	if err := os.WriteFile(chemin, []byte("2.50 1.00 0.50 1/100 42\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := lireCharge(chemin); got != "moyenne" {
		t.Errorf("lireCharge = %q, attendu moyenne", got)
	}
	if got := lireCharge(filepath.Join(dir, "absent")); got != "inconnue" {
		t.Errorf("fichier absent : %q, attendu inconnue", got)
	}
}

// fauxServeurTor répond au protocole du port de contrôle sur une socket locale.
func fauxServeurTor(t *testing.T, etabli bool) (adresse, cookie string) {
	t.Helper()
	dir := t.TempDir()
	cookie = filepath.Join(dir, "control_auth_cookie")
	if err := os.WriteFile(cookie, []byte("secret-de-test"), 0o600); err != nil {
		t.Fatal(err)
	}
	ecoute, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ecoute.Close() })
	go func() {
		for {
			c, err := ecoute.Accept()
			if err != nil {
				return
			}
			lecteur := make([]byte, 256)
			_ = c.SetDeadline(time.Now().Add(2 * time.Second))
			if _, err := c.Read(lecteur); err != nil {
				_ = c.Close()
				continue
			}
			_, _ = c.Write([]byte("250 OK\r\n"))
			if _, err := c.Read(lecteur); err != nil {
				_ = c.Close()
				continue
			}
			valeur := "0"
			if etabli {
				valeur = "1"
			}
			_, _ = c.Write([]byte("250-status/circuit-established=" + valeur + "\r\n250 OK\r\n"))
			_ = c.Close()
		}
	}()
	return ecoute.Addr().String(), cookie
}

func TestEtatTor(t *testing.T) {
	adresse, cookie := fauxServeurTor(t, true)
	if !etatTor(adresse, cookie, 2*time.Second) {
		t.Fatal("circuit établi non détecté")
	}
	adresse, cookie = fauxServeurTor(t, false)
	if etatTor(adresse, cookie, 2*time.Second) {
		t.Fatal("circuit absent détecté comme établi")
	}
	if etatTor(adresse, filepath.Join(t.TempDir(), "absent"), 2*time.Second) {
		t.Fatal("cookie absent accepté")
	}
}

func TestEtatCourantSansServices(t *testing.T) {
	e := etatCourant("1.2.3", "127.0.0.1:1", "127.0.0.1:1", "/nonexistent")
	if e.Logiciel != "TorDNS" || e.Version != "1.2.3" {
		t.Errorf("en-tête inattendu : %+v", e)
	}
	if e.Services["unbound"] != "indisponible" || e.Services["tor"] != "indisponible" {
		t.Errorf("services attendus indisponibles : %+v", e.Services)
	}
	switch e.Charge {
	case "faible", "moyenne", "forte", "inconnue":
	default:
		t.Errorf("charge inattendue : %q", e.Charge)
	}
}

// La page ne doit exposer ni compteur de requêtes ni nom de domaine.
func TestChampsPublics(t *testing.T) {
	e := etatCourant("0.8.0", "127.0.0.1:1", "127.0.0.1:1", "/nonexistent")
	if len(e.Services) != 2 {
		t.Errorf("services inattendus : %+v", e.Services)
	}
	if strings.Contains(strings.ToLower(e.Charge), "requete") {
		t.Error("la charge ne doit pas contenir de compteur")
	}
}
