package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"tordns/manifeste"
)

// TestManifesteDeRelease est piloté par scripts/verifier-m16.sh : il vérifie
// qu'un manifeste construit depuis une arborescence de release est accepté par
// le client, sans réseau. Il est ignoré en CI ordinaire.
func TestManifesteDeRelease(t *testing.T) {
	dossier := os.Getenv("TORDNS_VERIF_MANIFESTE_DIR")
	cle := os.Getenv("TORDNS_VERIF_CLE")
	if dossier == "" || cle == "" {
		t.Skip("pas de manifeste de release à vérifier")
	}
	brut, err := os.ReadFile(filepath.Join(dossier, "manifeste.json"))
	if err != nil {
		t.Fatal(err)
	}
	sig, err := os.ReadFile(filepath.Join(dossier, "manifeste.json.sig"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := manifeste.Accepter(brut, sig, cle, 0, time.Now())
	if err != nil {
		t.Fatalf("manifeste refusé : %v", err)
	}
	if _, ok := m.Cibles["client-linux-amd64"]; !ok {
		t.Fatalf("cible client-linux-amd64 absente : %v", m.Cibles)
	}
}
