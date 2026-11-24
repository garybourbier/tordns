package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func ecrire(t *testing.T, chemin, contenu string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(chemin), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(chemin, []byte(contenu), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestEtatSansDonnees(t *testing.T) {
	donnees := t.TempDir()
	code := t.TempDir()

	e := construire(donnees, code)
	if e.Logiciel != "TorDNS" {
		t.Fatalf("logiciel %q", e.Logiciel)
	}
	if e.Version != "inconnue" {
		t.Fatalf("version %q, attendu inconnue", e.Version)
	}
	if e.Adresse != "en préparation" {
		t.Fatalf("adresse %q", e.Adresse)
	}
	if e.Inscription != "absente" {
		t.Fatalf("inscription %q, attendu absente", e.Inscription)
	}
	if e.PremierBoot {
		t.Fatal("premier démarrage annoncé terminé sans marqueur")
	}
}

func TestEtatComplet(t *testing.T) {
	donnees := t.TempDir()
	code := t.TempDir()

	ecrire(t, filepath.Join(code, "noeud", "VERSION"), "0.8.0\n")
	ecrire(t, filepath.Join(donnees, "tor", "hs", "hostname"),
		"exempleexempleexempleexempleexempleexempleexempleexemple.onion\n")
	ecrire(t, filepath.Join(donnees, "premier-demarrage.ok"), "")
	ecrire(t, filepath.Join(donnees, "registre.json"),
		`{"adresse":"exemple.onion","etat":"quarantaine"}`)
	ecrire(t, filepath.Join(donnees, "maj-etat.json"), `{"version":"0.8.1"}`)

	e := construire(donnees, code)
	if e.Version != "0.8.0" {
		t.Fatalf("version %q", e.Version)
	}
	if e.Adresse != "exempleexempleexempleexempleexempleexempleexempleexemple.onion" {
		t.Fatalf("adresse %q", e.Adresse)
	}
	if e.Inscription != "quarantaine" {
		t.Fatalf("inscription %q", e.Inscription)
	}
	if !e.PremierBoot {
		t.Fatal("marqueur de premier démarrage ignoré")
	}
	if e.MiseAJour != "version 0.8.1 disponible" {
		t.Fatalf("mises à jour %q", e.MiseAJour)
	}

	// Le JSON doit rester court et ne contenir aucun nom de requête.
	brut, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if len(brut) > 512 {
		t.Fatalf("état de %d octets, trop bavard", len(brut))
	}
}

func TestRegistreIllisible(t *testing.T) {
	donnees := t.TempDir()
	ecrire(t, filepath.Join(donnees, "registre.json"), "pas du json")
	if e := construire(donnees, t.TempDir()); e.Inscription != "absente" {
		t.Fatalf("inscription %q, attendu absente", e.Inscription)
	}
}

func TestMiseAJourJouee(t *testing.T) {
	donnees := t.TempDir()
	ecrire(t, filepath.Join(donnees, "maj-etat.json"), `{"jouee":"0.8.0"}`)
	if e := construire(donnees, t.TempDir()); e.MiseAJour != "à jour (0.8.0)" {
		t.Fatalf("mises à jour %q", e.MiseAJour)
	}
}
