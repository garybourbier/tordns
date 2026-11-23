//go:build darwin

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func executer(nom string, args ...string) (string, error) {
	sortie, err := exec.Command(nom, args...).CombinedOutput()
	if err != nil {
		return string(sortie), fmt.Errorf("%s : %w (%s)", strings.Join(append([]string{nom}, args...), " "), err, strings.TrimSpace(string(sortie)))
	}
	return string(sortie), nil
}

func servicesReseau() ([]string, error) { return servicesReseauAvec(executer) }

func preparerEtatDNS(chemin string, services []string) (etatDNS, error) {
	return preparerEtatAvec(executer, chemin, services)
}

func appliquerDNS(services, adresses []string) error {
	return appliquerDNSAvec(executer, services, adresses)
}

func restaurerDNS(etat etatDNS) error { return restaurerDNSAvec(executer, etat) }

func restaurerDepuisEtat(chemin string) error {
	etat, err := lireEtatDNS(chemin)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if err := restaurerDNS(etat); err != nil {
		return err
	}
	return os.Remove(chemin)
}

func diagnosticer() []constat {
	texte, err := executer("scutil", "--dns")
	if err != nil {
		return []constat{{true, "scutil --dns illisible : " + err.Error()}}
	}
	return analyserScutil(texte)
}
