package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCentilesFenetreEtHistorique(t *testing.T) {
	maintenant := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	r := &reseau{etat: etatReseauInterne{Derniers: map[string]bool{}}}
	for i := 1; i <= 100; i++ {
		r.ajouterSonde(categorieCommunaute, "abcdefghij.onion", []mesureSonde{{
			Delai: time.Duration(i) * time.Millisecond, Correct: true, Joignable: true,
		}}, true, maintenant)
	}
	// Une mesure de plus de 24 h ne doit pas peser sur les percentiles.
	r.etat.Echantillons = append(r.etat.Echantillons, echantillon{
		Temps: maintenant.Add(-25 * time.Hour), Categorie: categorieCommunaute,
		Adresse: "abcdefghij.onion", DelaiMs: 9999, Correct: false, Joignable: true,
	})
	resume := r.resumeLocked(maintenant)[categorieCommunaute]
	if resume.Sondes != 100 {
		t.Fatalf("sondes sur 24 h = %d, attendu 100", resume.Sondes)
	}
	if resume.DelaiMedian != 50 || resume.DelaiP95 != 95 {
		t.Fatalf("percentiles = %v / %v, attendu 50 / 95", resume.DelaiMedian, resume.DelaiP95)
	}
	if resume.TauxDNSSEC != 1 {
		t.Fatalf("taux DNSSEC = %v, attendu 1", resume.TauxDNSSEC)
	}

	r.purger(maintenant)
	if len(r.etat.Historique) != 1 {
		t.Fatalf("historique = %d heures, attendu 1", len(r.etat.Historique))
	}
	if got := r.etat.Historique[0].Communaute.Sondes; got != 100 {
		t.Fatalf("agrégat horaire = %d sondes, attendu 100", got)
	}

	// La purge à 30 jours ne garde que les agrégats récents.
	r.etat.Historique = append(r.etat.Historique, agregatHoraire{
		Heure: maintenant.Add(-31 * 24 * time.Hour),
		Coeur: agregatCategorie{Sondes: 1},
	})
	r.purger(maintenant)
	if len(r.etat.Historique) != 1 || r.etat.Historique[0].Heure.Before(maintenant.Add(-historiqueMax)) {
		t.Fatalf("historique non purgé à 30 jours : %+v", r.etat.Historique)
	}
}

func TestDatePublicationOnionbalance(t *testing.T) {
	chemin := filepath.Join(t.TempDir(), "statut.sock")
	ecoute, err := net.Listen("unix", chemin)
	if err != nil {
		t.Fatal(err)
	}
	defer ecoute.Close()
	go func() {
		conn, err := ecoute.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte(`{"services":[{"publishAttemptFirstDescriptor":"2026-11-24 11:40:00","publishAttemptSecondDescriptor":"2026-11-24 11:42:03","instances":[{"onionAddress":"ne-doit-pas-sortir.onion"}]}]}`))
	}()
	temps, ok := datePublicationOnionbalance(chemin)
	if !ok || !temps.Equal(time.Date(2026, 11, 24, 11, 42, 3, 0, time.UTC)) {
		t.Fatalf("date Onionbalance = %v (ok=%v)", temps, ok)
	}
}

func TestEtatReseauPublicTronqueEtSansDonneesPersonnelles(t *testing.T) {
	dir := t.TempDir()
	maintenant := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	communautaire := strings.Repeat("a", 56) + ".onion"
	coeur := strings.Repeat("z", 56) + ".onion"
	coeurFichier := filepath.Join(dir, "coeur.txt")
	if err := os.WriteFile(coeurFichier, []byte("# test\n"+coeur+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	descripteur := filepath.Join(dir, "descripteur.date")
	if err := os.WriteFile(descripteur, []byte("ok\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dateDescripteur := maintenant.Add(-17 * time.Minute)
	if err := os.Chtimes(descripteur, dateDescripteur, dateDescripteur); err != nil {
		t.Fatal(err)
	}

	reseauFichier := filepath.Join(dir, "etat-reseau.json")
	r, err := nouveauRegistre(filepath.Join(dir, "registre.json"), "", config{
		Maintenant:           func() time.Time { return maintenant },
		CoeurFichier:         coeurFichier,
		DescripteurFichier:   descripteur,
		ReseauFichier:        reseauFichier,
		ReseauInterneFichier: filepath.Join(dir, "reseau-interne.json"),
		Domaines:             []string{"exemple.test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	r.etat.Admis[communautaire] = &admis{Adresse: communautaire, Depuis: maintenant, SondesOK: 1, Disponible: 1}
	r.etat.Candidats["candidat.onion"] = &candidat{
		Adresse: "candidat.onion", Contact: "personne@example.test", Defi: "secret",
	}
	r.reseau.ajouterSonde(categorieCommunaute, communautaire, []mesureSonde{{
		Delai: 12 * time.Millisecond, Correct: true, Joignable: true,
	}}, true, maintenant)
	r.reseau.ajouterSonde(categorieCoeur, coeur, []mesureSonde{{
		Delai: 20 * time.Millisecond, Correct: true, Joignable: true,
	}}, true, maintenant)
	if err := r.publierReseau(maintenant); err != nil {
		t.Fatal(err)
	}

	brut, err := os.ReadFile(reseauFichier)
	if err != nil {
		t.Fatal(err)
	}
	texte := string(brut)
	for _, interdit := range []string{communautaire, coeur, "personne@example.test", "secret", "exemple.test", "contact", "defi", "doutes"} {
		if strings.Contains(texte, interdit) {
			t.Fatalf("le JSON public contient %q :\n%s", interdit, texte)
		}
	}
	if !strings.Contains(texte, "aaaaaaaa…") || !strings.Contains(texte, "zzzzzzzz…") {
		t.Fatalf("adresses tronquées absentes :\n%s", texte)
	}
	var public etatReseauPublic
	if err := json.Unmarshal(brut, &public); err != nil {
		t.Fatal(err)
	}
	if public.DernierePublicationDescripteur == nil || !public.DernierePublicationDescripteur.Equal(dateDescripteur.UTC()) {
		t.Fatalf("date de descripteur = %v, attendu %v", public.DernierePublicationDescripteur, dateDescripteur)
	}
	if len(public.Historique) == 0 {
		t.Fatal("historique horaire vide")
	}

	// Les deux surfaces HTTP ne doivent pas exposer les adresses complètes ni
	// de script : la page est rendue côté serveur, sans JavaScript.
	for _, chemin := range []string{"/reseau.json", "/reseau"} {
		req := httptest.NewRequest(http.MethodGet, chemin, nil)
		rec := httptest.NewRecorder()
		r.routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s : code %d", chemin, rec.Code)
		}
		corps := rec.Body.String()
		if strings.Contains(corps, communautaire) || strings.Contains(corps, coeur) {
			t.Fatalf("%s expose une adresse complète", chemin)
		}
		if strings.Contains(corps, "<script") || strings.Contains(corps, "onclick=") {
			t.Fatalf("%s contient du JavaScript", chemin)
		}
		if chemin == "/reseau" {
			if !strings.Contains(corps, "<svg") || !strings.Contains(corps, "aaaaaaaa…") {
				t.Fatalf("page /reseau sans graphique ou sans adresse tronquée")
			}
		}
	}
}
