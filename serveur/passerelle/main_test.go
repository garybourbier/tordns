package main

import (
	"testing"
	"time"
)

func TestCircuitDepuisEntete(t *testing.T) {
	cas := []struct {
		valeur  string
		attendu uint32
		ok      bool
	}{
		// Tor place l'identifiant de circuit sur les 32 derniers bits.
		{"fc00:dead:beef:4dad::1:2", 0x00010002, true},
		{"fc00:dead:beef:4dad:0:0:ffff:ffff", 0xffffffff, true},
		{"127.0.0.1", 0x7f000001, true},
		{"", 0, false},
		{"pas-une-ip", 0, false},
	}
	for _, c := range cas {
		got, ok := circuitDepuisEntete(c.valeur)
		if ok != c.ok || (ok && got != c.attendu) {
			t.Errorf("circuitDepuisEntete(%q) = (%#x, %v), attendu (%#x, %v)", c.valeur, got, ok, c.attendu, c.ok)
		}
	}
}

func TestLimiteurCircuitsIsoleLesCircuits(t *testing.T) {
	l := nouveauLimiteurCircuits(1, 2, 16, time.Minute)
	if !l.autoriser(1) || !l.autoriser(1) {
		t.Fatal("les deux premiers jetons du circuit 1 devraient passer")
	}
	if l.autoriser(1) {
		t.Fatal("le troisième appel du circuit 1 devrait être refusé (rafale 2)")
	}
	if !l.autoriser(2) {
		t.Fatal("le circuit 2 ne doit pas être pénalisé par le circuit 1")
	}
}

func TestLimiteurCircuitsTableBornee(t *testing.T) {
	l := nouveauLimiteurCircuits(1, 2, 1, time.Minute)
	if !l.autoriser(1) {
		t.Fatal("le premier circuit devrait être admis")
	}
	if l.autoriser(2) {
		t.Fatal("un second circuit devrait être refusé quand la table est pleine")
	}
	if !l.autoriser(1) {
		t.Fatal("le circuit déjà présent doit continuer à passer")
	}
}
