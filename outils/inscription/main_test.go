package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInscriptionComplete(t *testing.T) {
	var recus []string
	var adresse string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var corps map[string]string
		_ = json.NewDecoder(r.Body).Decode(&corps)
		recus = append(recus, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/inscription":
			adresse = corps["adresse_instance"]
			_ = json.NewEncoder(w).Encode(map[string]any{
				"etat": "candidat", "adresse": adresse, "defi": "defi-jetable",
				"page": "http://registre.onion/", "quarantaine_secondes": 3600,
			})
		case "/inscription/confirmer":
			if adresse == "" {
				t.Error("confirmation avant inscription")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"etat": "confirme", "adresse": adresse, "quarantaine_secondes": 3600,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer s.Close()

	defi := filepath.Join(t.TempDir(), "tor", "defi")
	r, err := executer(s.URL, "abcdefghijklmnop.onion", "", defi, "")
	if err != nil {
		t.Fatal(err)
	}
	if r.Etat != "confirme" {
		t.Fatalf("état = %q", r.Etat)
	}
	if strings.Join(recus, ",") != "/inscription,/inscription/confirmer" {
		t.Fatalf("ordre des appels : %v", recus)
	}
	brut, err := os.ReadFile(defi)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(brut)) != "defi-jetable" {
		t.Fatalf("défi écrit = %q", brut)
	}
}

func TestRefusRegistre(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_ = json.NewEncoder(w).Encode(map[string]string{"erreur": "adresse évincée"})
	}))
	defer s.Close()
	_, err := executer(s.URL, "abcdefghijklmnop.onion", "", filepath.Join(t.TempDir(), "defi"), "")
	if err == nil || !strings.Contains(err.Error(), "adresse évincée") {
		t.Fatalf("refus non propagé : %v", err)
	}
}
