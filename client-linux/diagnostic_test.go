package main

import (
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func ecrireFichier(t *testing.T, racine, chemin, contenu string) {
	t.Helper()
	c := filepath.Join(racine, chemin)
	if err := os.MkdirAll(filepath.Dir(c), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(c, []byte(contenu), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDiagnosticMachineQuiFuit(t *testing.T) {
	racine := t.TempDir()
	ecrireFichier(t, racine, "etc/resolv.conf", "nameserver 192.0.2.53\nnameserver ::1\n")
	ecrireFichier(t, racine, "run/systemd/resolve/stub-resolv.conf", "nameserver 127.0.0.53\n")
	ecrireFichier(t, racine, "etc/chromium/policies/managed/doh.json",
		`{"DnsOverHttpsMode":"secure"}`)
	constats := diagnosticer(racine)
	fuites := 0
	var textes []string
	for _, c := range constats {
		textes = append(textes, c.texte)
		if c.fuite {
			fuites++
		}
	}
	if fuites < 4 {
		t.Fatalf("%d fuites, attendu au moins 4 : %v", fuites, textes)
	}
	joint := strings.Join(textes, "\n")
	for _, attendu := range []string{"192.0.2.53", "::1", "systemd-resolved", "DoH"} {
		if !strings.Contains(joint, attendu) {
			t.Fatalf("constat manquant pour %q :\n%s", attendu, joint)
		}
	}
	if afficherDiagnostic(constats) == 0 {
		t.Fatal("le bilan doit signaler les fuites")
	}
}

func TestDiagnosticMachineCorrigee(t *testing.T) {
	racine := t.TempDir()
	ecrireFichier(t, racine, "etc/resolv.conf", "nameserver 127.0.0.1\n")
	constats := diagnosticer(racine)
	for _, c := range constats {
		if c.fuite {
			t.Fatalf("fuite inattendue sur une machine corrigée : %s", c.texte)
		}
	}
	if afficherDiagnostic(constats) != 0 {
		t.Fatal("aucune fuite ne doit être comptée")
	}
}

func TestDiagnosticPolitiqueDoHDesactivee(t *testing.T) {
	racine := t.TempDir()
	ecrireFichier(t, racine, "etc/resolv.conf", "nameserver 127.0.0.1\n")
	ecrireFichier(t, racine, "etc/chromium/policies/managed/doh.json",
		`{"DnsOverHttpsMode":"off"}`)
	for _, c := range diagnosticer(racine) {
		if c.fuite {
			t.Fatalf("une politique DoH « off » ne doit pas compter : %s", c.texte)
		}
	}
}

func TestPaquetsDnsHostiles(t *testing.T) {
	hasard := rand.New(rand.NewSource(13))
	for i := 0; i < 10_000; i++ {
		msg := make([]byte, hasard.Intn(600))
		hasard.Read(msg)
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("boucle %d, %d octets : panique %v", i, len(msg), r)
				}
			}()
			_, _ = analyser(msg)
			_, _ = cacheable(msg, 3600*1e9)
			_ = ajuster(msg, 1, 12*time.Second)
			_ = servfail(msg)
		}()
	}
}
