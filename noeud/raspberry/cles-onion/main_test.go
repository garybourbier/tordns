package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestFormatTor(t *testing.T) {
	pub, priv, err := generer()
	if err != nil {
		t.Fatal(err)
	}
	if len(pub) != 32 || len(priv) != 64 {
		t.Fatalf("tailles inattendues : pub %d, priv %d", len(pub), len(priv))
	}

	dir := t.TempDir()
	if err := ecrire(dir, pub, priv); err != nil {
		t.Fatal(err)
	}

	sec, err := os.ReadFile(filepath.Join(dir, "hs_ed25519_secret_key"))
	if err != nil {
		t.Fatal(err)
	}
	if len(sec) != len(prefixeSecret)+64 {
		t.Fatalf("clé secrète de %d octets, attendu %d", len(sec), len(prefixeSecret)+64)
	}
	if string(sec[:len(prefixeSecret)]) != prefixeSecret {
		t.Fatalf("en-tête inattendu : %q", sec[:len(prefixeSecret)])
	}
	if !bytes.Equal(sec[len(prefixeSecret):], priv) {
		t.Fatal("la clé privée écrite diffère de celle générée")
	}

	pubFile, err := os.ReadFile(filepath.Join(dir, "hs_ed25519_public_key"))
	if err != nil {
		t.Fatal(err)
	}
	if len(pubFile) != len(prefixePublic)+32 {
		t.Fatalf("clé publique de %d octets, attendu %d", len(pubFile), len(prefixePublic)+32)
	}
	if !bytes.Equal(pubFile[len(prefixePublic):], pub) {
		t.Fatal("la clé publique écrite diffère de celle générée")
	}

	infos, err := os.Stat(filepath.Join(dir, "hs_ed25519_secret_key"))
	if err != nil {
		t.Fatal(err)
	}
	if infos.Mode().Perm() != 0o600 {
		t.Fatalf("clé secrète en %o, attendu 600", infos.Mode().Perm())
	}
}

func TestRefuseDEcraser(t *testing.T) {
	pub, priv, err := generer()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := ecrire(dir, pub, priv); err != nil {
		t.Fatal(err)
	}

	pub2, priv2, err := generer()
	if err != nil {
		t.Fatal(err)
	}
	if err := ecrire(dir, pub2, priv2); err == nil {
		t.Fatal("une seconde écriture aurait dû être refusée")
	}

	sec, err := os.ReadFile(filepath.Join(dir, "hs_ed25519_secret_key"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sec[len(prefixeSecret):], priv) {
		t.Fatal("la clé du nœud a changé")
	}
}

func TestDeuxIdentitesDifferent(t *testing.T) {
	a, _, err := generer()
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := generer()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("deux générations donnent la même clé publique")
	}
}
