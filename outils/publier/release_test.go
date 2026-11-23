package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func ecrireSommes(t *testing.T, dossier string, noms []string) {
	t.Helper()
	var lignes []string
	for _, nom := range noms {
		brut, err := os.ReadFile(filepath.Join(dossier, nom))
		if err != nil {
			t.Fatal(err)
		}
		somme := sha256.Sum256(brut)
		lignes = append(lignes, hex.EncodeToString(somme[:])+"  "+nom)
	}
	if err := os.WriteFile(filepath.Join(dossier, "SHA256SUMS"), []byte(strings.Join(lignes, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestNomCible(t *testing.T) {
	cas := map[string]string{
		"tordns-client-0.8.0-linux-amd64.tar.gz":       "client-linux-amd64",
		"tordns-client-0.8.0-linux-armv7.tar.gz":       "client-linux-armv7",
		"tordns-client-0.8.0-windows-x86_64-setup.exe": "client-windows-x86_64",
		"tordns-client-0.8.0-macos-universel":          "client-macos",
		"tordns-client-0.8.0-android-arm64-v8a.apk":    "client-android-arm64-v8a",
		"tordns-client-0.8.0-android-universel.apk":    "client-android-universel",
		"tordns-client-0.8.0-macos-universel.pkg":      "client-macos-pkg",
		"autre.txt": "",
	}
	for fichier, attendu := range cas {
		if obtenu := nomCible(fichier); obtenu != attendu {
			t.Errorf("%s : cible %q, attendu %q", fichier, obtenu, attendu)
		}
	}
}

func TestManifesteDepuisReleaseLocale(t *testing.T) {
	dossier := t.TempDir()
	noms := []string{
		"tordns-client-0.0.0-test-linux-amd64.tar.gz",
		"tordns-client-0.0.0-test-linux-arm64.tar.gz",
		"tordns-client-0.0.0-test-windows-x86_64-setup.exe",
		"tordns-client-0.0.0-test-android-universel.apk",
		"tordns-client-0.0.0-test-macos-universel",
	}
	for _, nom := range noms {
		if err := os.WriteFile(filepath.Join(dossier, nom), []byte("contenu "+nom), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	ecrireSommes(t, dossier, noms)
	images := "registre=ghcr.io/garybourbier/tordns-registre@sha256:" + strings.Repeat("a", 64) + "\n"
	if err := os.WriteFile(filepath.Join(dossier, "images.txt"), []byte(images), 0o644); err != nil {
		t.Fatal(err)
	}

	cibles, imgs, err := manifesteDepuisRelease(dossier, "https://exemple.invalid/releases/v0.0.0-test", false)
	if err != nil {
		t.Fatal(err)
	}
	for _, nom := range []string{"client-linux-amd64", "client-linux-arm64", "client-windows-x86_64", "client-android-universel", "client-macos"} {
		if _, ok := cibles[nom]; !ok {
			t.Errorf("cible %s absente", nom)
		}
	}
	if cibles["client-linux-amd64"].URL != "https://exemple.invalid/releases/v0.0.0-test/tordns-client-0.0.0-test-linux-amd64.tar.gz" {
		t.Errorf("URL inattendue : %s", cibles["client-linux-amd64"].URL)
	}
	if imgs["registre"] == "" {
		t.Error("image registre absente")
	}
}

func TestManifesteDepuisReleaseRefuseFichierAltere(t *testing.T) {
	dossier := t.TempDir()
	nom := "tordns-client-0.0.0-test-linux-amd64.tar.gz"
	chemin := filepath.Join(dossier, nom)
	if err := os.WriteFile(chemin, []byte("avant"), 0o644); err != nil {
		t.Fatal(err)
	}
	ecrireSommes(t, dossier, []string{nom})
	if err := os.WriteFile(chemin, []byte("après"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := manifesteDepuisRelease(dossier, "https://exemple.invalid", false); err == nil {
		t.Fatal("fichier altéré accepté")
	}
}

func TestLireSommesRefuseTraversee(t *testing.T) {
	dossier := t.TempDir()
	contenu := strings.Repeat("a", 64) + "  ../evasion\n"
	if err := os.WriteFile(filepath.Join(dossier, "SHA256SUMS"), []byte(contenu), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := lireSommes(filepath.Join(dossier, "SHA256SUMS")); err == nil {
		t.Fatal("traversée acceptée")
	}
}
