package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixture(t *testing.T, nom string) string {
	t.Helper()
	brut, err := os.ReadFile(filepath.Join("testdata", nom))
	if err != nil {
		t.Fatal(err)
	}
	return string(brut)
}

func TestParserServicesReseau(t *testing.T) {
	services := parserServices(fixture(t, "networksetup-services.txt"))
	if len(services) != 2 || services[0] != "Wi-Fi" || services[1] != "Thunderbolt Bridge" {
		t.Fatalf("services = %v", services)
	}
}

func TestParserDNSServers(t *testing.T) {
	if got := parserDNSServers("There aren't any DNS Servers set on Wi-Fi.\n"); len(got) != 0 {
		t.Fatalf("aucun DNS : %v", got)
	}
	got := parserDNSServers("1.1.1.1\n8.8.8.8\n")
	if len(got) != 2 || got[0] != "1.1.1.1" || got[1] != "8.8.8.8" {
		t.Fatalf("DNS = %v", got)
	}
}

func TestSauvegardeApplicationRestauration(t *testing.T) {
	appels := make([][]string, 0)
	exec := func(nom string, args ...string) (string, error) {
		appels = append(appels, append([]string{nom}, args...))
		if len(args) >= 2 && args[0] == "-getdnsservers" && args[1] == "Wi-Fi" {
			return "1.1.1.1\n", nil
		}
		if len(args) >= 2 && args[0] == "-getdnsservers" {
			return "There aren't any DNS Servers set.\n", nil
		}
		return "", nil
	}
	services := []string{"Pont", "Wi-Fi"}
	etat, err := sauvegarderDNSAvec(exec, services)
	if err != nil {
		t.Fatal(err)
	}
	if len(etat.Services["Wi-Fi"]) != 1 || len(etat.Services["Pont"]) != 0 {
		t.Fatalf("état = %+v", etat)
	}
	if err := appliquerDNSAvec(exec, services, []string{"127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	if err := restaurerDNSAvec(exec, etat); err != nil {
		t.Fatal(err)
	}
	var restorePont, restoreWiFi bool
	for _, a := range appels {
		joint := strings.Join(a, " ")
		if joint == "networksetup -setdnsservers Pont Empty" {
			restorePont = true
		}
		if joint == "networksetup -setdnsservers Wi-Fi 1.1.1.1" {
			restoreWiFi = true
		}
	}
	if !restorePont || !restoreWiFi {
		t.Fatalf("restauration incomplète : %v", appels)
	}
}

func TestEtatDNSExistantNEstPasEcrase(t *testing.T) {
	dossier := t.TempDir()
	chemin := filepath.Join(dossier, "dns.json")
	if err := ecrireEtatDNS(chemin, etatDNS{Services: map[string][]string{"Wi-Fi": {"192.0.2.1"}}}); err != nil {
		t.Fatal(err)
	}
	appele := false
	exec := func(string, ...string) (string, error) {
		appele = true
		return "", nil
	}
	etat, err := preparerEtatAvec(exec, chemin, []string{"Wi-Fi"})
	if err != nil {
		t.Fatal(err)
	}
	if appele {
		t.Fatal("les DNS ont été resauvegardés alors que l'état existait")
	}
	if len(etat.Services["Wi-Fi"]) != 1 || etat.Services["Wi-Fi"][0] != "192.0.2.1" {
		t.Fatalf("état écrasé : %+v", etat)
	}
	if info, err := os.Stat(dossier); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("dossier d'état non privé : %v %v", info, err)
	}
}

func TestAnalyseScutil(t *testing.T) {
	fuites := analyserScutil(fixture(t, "scutil-fuite.txt"))
	// ::1 est la boucle locale, donc acceptable ; seul 192.0.2.53 fuit.
	if len(fuites) != 1 {
		t.Fatalf("fuites = %+v", fuites)
	}
	for _, c := range fuites {
		if !c.fuite || !strings.Contains(c.texte, "192.0.2.53") {
			t.Fatalf("constat inattendu : %+v", c)
		}
	}
	if got := analyserScutil(fixture(t, "scutil-local.txt")); len(got) != 0 {
		t.Fatalf("boucle locale signalée : %+v", got)
	}
	if got := analyserScutil("DNS configuration\n"); len(got) != 1 || !got[0].fuite {
		t.Fatalf("absence de résolveur non signalée : %+v", got)
	}
}
