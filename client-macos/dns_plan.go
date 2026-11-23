package main

// Gestion des DNS macOS, séparée des appels système pour être testable sur
// Linux : networksetup est injecté sous forme de fonction.

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type executeur func(nom string, args ...string) (string, error)

type etatDNS struct {
	Services map[string][]string `json:"services"`
}

type constat struct {
	fuite bool
	texte string
}

// parserServices lit la sortie de `networksetup -listallnetworkservices`.
// Les services désactivés (préfixés par *) ne sont pas touchés.
func parserServices(texte string) []string {
	var services []string
	for _, ligne := range strings.Split(texte, "\n") {
		ligne = strings.TrimSpace(ligne)
		if ligne == "" || strings.HasPrefix(ligne, "An asterisk") || strings.HasPrefix(ligne, "*") {
			continue
		}
		services = append(services, ligne)
	}
	return services
}

// parserDNSServers lit la sortie de `networksetup -getdnsservers <service>`.
func parserDNSServers(texte string) []string {
	var adresses []string
	for _, ligne := range strings.Split(texte, "\n") {
		ligne = strings.TrimSpace(ligne)
		if ligne == "" || strings.Contains(ligne, "aren't any DNS Servers") {
			continue
		}
		adresses = append(adresses, ligne)
	}
	return adresses
}

func servicesReseauAvec(exec executeur) ([]string, error) {
	texte, err := exec("networksetup", "-listallnetworkservices")
	if err != nil {
		return nil, err
	}
	services := parserServices(texte)
	if len(services) == 0 {
		return nil, errors.New("aucun service réseau actif")
	}
	sort.Strings(services)
	return services, nil
}

func sauvegarderDNSAvec(exec executeur, services []string) (etatDNS, error) {
	etat := etatDNS{Services: map[string][]string{}}
	for _, service := range services {
		texte, err := exec("networksetup", "-getdnsservers", service)
		if err != nil {
			return etatDNS{}, fmt.Errorf("%s : %w", service, err)
		}
		etat.Services[service] = parserDNSServers(texte)
	}
	return etat, nil
}

func appliquerDNSAvec(exec executeur, services []string, adresses []string) error {
	for _, service := range services {
		args := append([]string{"-setdnsservers", service}, adresses...)
		if _, err := exec("networksetup", args...); err != nil {
			return fmt.Errorf("%s : %w", service, err)
		}
	}
	return nil
}

func restaurerDNSAvec(exec executeur, etat etatDNS) error {
	services := make([]string, 0, len(etat.Services))
	for service := range etat.Services {
		services = append(services, service)
	}
	sort.Strings(services)
	for _, service := range services {
		adresses := etat.Services[service]
		if len(adresses) == 0 {
			adresses = []string{"Empty"}
		}
		args := append([]string{"-setdnsservers", service}, adresses...)
		if _, err := exec("networksetup", args...); err != nil {
			return fmt.Errorf("%s : %w", service, err)
		}
	}
	return nil
}

func lireEtatDNS(chemin string) (etatDNS, error) {
	var etat etatDNS
	brut, err := os.ReadFile(chemin)
	if err != nil {
		return etat, err
	}
	if err := json.Unmarshal(brut, &etat); err != nil {
		return etat, err
	}
	if etat.Services == nil {
		etat.Services = map[string][]string{}
	}
	return etat, nil
}

func ecrireEtatDNS(chemin string, etat etatDNS) error {
	if err := os.MkdirAll(filepath.Dir(chemin), 0o700); err != nil {
		return err
	}
	_ = os.Chmod(filepath.Dir(chemin), 0o700)
	brut, err := json.MarshalIndent(etat, "", "  ")
	if err != nil {
		return err
	}
	brut = append(brut, '\n')
	tmp := chemin + ".tmp"
	if err := os.WriteFile(tmp, brut, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, chemin)
}

// preparerEtatAvec conserve les DNS d'origine. Un état existant n'est jamais
// écrasé : un redémarrage du service ne doit pas sauvegarder 127.0.0.1 comme
// valeur d'origine.
func preparerEtatAvec(exec executeur, chemin string, services []string) (etatDNS, error) {
	if etat, err := lireEtatDNS(chemin); err == nil {
		return etat, nil
	}
	etat, err := sauvegarderDNSAvec(exec, services)
	if err != nil {
		return etatDNS{}, err
	}
	if err := ecrireEtatDNS(chemin, etat); err != nil {
		return etatDNS{}, err
	}
	return etat, nil
}

// analyserScutil extrait les résolveurs de `scutil --dns` et signale tout
// résolveur qui n'est pas la boucle locale.
func analyserScutil(texte string) []constat {
	var adresses []string
	sc := bufio.NewScanner(strings.NewReader(texte))
	for sc.Scan() {
		ligne := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(ligne, "nameserver[") {
			continue
		}
		_, valeur, ok := strings.Cut(ligne, ":")
		if !ok {
			continue
		}
		adresse := strings.TrimSpace(valeur)
		if adresse != "" {
			adresses = append(adresses, adresse)
		}
	}
	if len(adresses) == 0 {
		return []constat{{true, "scutil --dns ne montre aucun résolveur : le DNS système échappe au diagnostic."}}
	}
	var constats []constat
	for _, adresse := range adresses {
		if adresse == "127.0.0.1" || adresse == "::1" {
			continue
		}
		constats = append(constats, constat{true,
			"résolveur système " + adresse + " : les requêtes passent à côté de TorDNS."})
	}
	return constats
}

func afficherDiagnostic(constats []constat) int {
	fuites := 0
	for _, c := range constats {
		etiquette := "OK"
		if c.fuite {
			etiquette = "FUITE"
			fuites++
		}
		fmt.Printf("[%s] %s\n", etiquette, c.texte)
	}
	if fuites == 0 {
		fmt.Println("Bilan : aucun résolveur hors boucle locale détecté.")
	} else {
		fmt.Printf("Bilan : %d fuite(s) DNS à fermer.\n", fuites)
	}
	return fuites
}
