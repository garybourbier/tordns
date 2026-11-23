// Construction d'un manifeste depuis une release (Mission 16).
//
// Le dossier peut être une release déjà téléchargée (tests, reprise hors
// ligne) ou un tag : dans ce dernier cas `gh release download` récupère la
// release brouillon. Aucun secret n'est lu ; gh utilise sa session existante.
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"tordns/manifeste"
)

var (
	reLigneSomme = regexp.MustCompile(`^([0-9a-f]{64})[[:space:]]+\*?(.+)$`)
	reTagVersion = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$`)
)

// nomCible traduit le nom d'un fichier publié en nom de cible du manifeste.
// Une chaîne vide signifie que le fichier n'est pas une cible de mise à jour.
func nomCible(fichier string) string {
	base := filepath.Base(fichier)
	switch {
	case strings.Contains(base, "-linux-amd64.tar.gz"):
		return "client-linux-amd64"
	case strings.Contains(base, "-linux-arm64.tar.gz"):
		return "client-linux-arm64"
	case strings.Contains(base, "-linux-armv7.tar.gz"):
		return "client-linux-armv7"
	case strings.Contains(base, "-linux-amd64.deb"):
		return "client-linux-amd64-deb"
	case strings.Contains(base, "-linux-arm64.deb"):
		return "client-linux-arm64-deb"
	case strings.Contains(base, "-windows-x86_64-setup.exe"):
		return "client-windows-x86_64"
	case strings.Contains(base, "-windows-aarch64-setup.exe"):
		return "client-windows-aarch64"
	case strings.Contains(base, "-macos-universel.pkg"):
		return "client-macos-pkg"
	case strings.Contains(base, "-macos-universel"):
		return "client-macos"
	case strings.Contains(base, "-android-arm64-v8a.apk"):
		return "client-android-arm64-v8a"
	case strings.Contains(base, "-android-armeabi-v7a.apk"):
		return "client-android-armeabi-v7a"
	case strings.Contains(base, "-android-x86_64.apk"):
		return "client-android-x86_64"
	case strings.Contains(base, "-android-universel.apk"):
		return "client-android-universel"
	case strings.Contains(base, "-noeud-") && strings.HasSuffix(base, ".tar.gz"):
		return "noeud"
	}
	return ""
}

// lireSommes refuse un fichier absent, une ligne invalide ou un doublon.
func lireSommes(chemin string) (map[string]string, error) {
	f, err := os.Open(chemin)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sommes := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		ligne := strings.TrimSpace(sc.Text())
		if ligne == "" {
			continue
		}
		m := reLigneSomme.FindStringSubmatch(ligne)
		if m == nil {
			return nil, fmt.Errorf("ligne SHA256SUMS invalide : %q", ligne)
		}
		nom := m[2]
		if strings.ContainsAny(nom, `/\`) || nom == "" {
			return nil, fmt.Errorf("nom de fichier refusé : %q", nom)
		}
		if _, existe := sommes[nom]; existe {
			return nil, fmt.Errorf("fichier présent deux fois dans SHA256SUMS : %s", nom)
		}
		sommes[nom] = m[1]
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(sommes) == 0 {
		return nil, errors.New("SHA256SUMS vide")
	}
	return sommes, nil
}

func verifierSomme(chemin, attendu string) error {
	f, err := os.Open(chemin)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	obtenu := hex.EncodeToString(h.Sum(nil))
	if obtenu != attendu {
		return fmt.Errorf("%s : SHA-256 %s, attendu %s", filepath.Base(chemin), obtenu, attendu)
	}
	return nil
}

func lireImages(chemin string) (map[string]string, error) {
	f, err := os.Open(chemin)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	images := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		ligne := strings.TrimSpace(sc.Text())
		if ligne == "" || strings.HasPrefix(ligne, "#") {
			continue
		}
		nom, ref, ok := strings.Cut(ligne, "=")
		if !ok || nom == "" || ref == "" {
			return nil, fmt.Errorf("ligne images.txt invalide : %q", ligne)
		}
		images[nom] = ref
	}
	return images, sc.Err()
}

func telechargerRelease(tag, dossier string) error {
	if !reTagVersion.MatchString(tag) {
		return fmt.Errorf("tag de release invalide : %q", tag)
	}
	gh, err := exec.LookPath("gh")
	if err != nil {
		return errors.New("gh requis pour télécharger une release brouillon")
	}
	cmd := exec.Command(gh, "release", "download", tag, "--repo", "garybourbier/tordns", "--dir", dossier)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("téléchargement de la release %s : %w", tag, err)
	}
	return nil
}

func verifierAttestation(gh, chemin string) error {
	cmd := exec.Command(gh, "attestation", "verify", chemin, "--repo", "garybourbier/tordns")
	cmd.Stdout = io.Discard
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("attestation refusée pour %s : %w", filepath.Base(chemin), err)
	}
	return nil
}

// manifesteDepuisRelease construit les cibles et images depuis un dossier de
// release ou un tag. Les attestations ne sont vérifiées que si demandé ; le
// mode dossier local les désactive par défaut dans la commande.
func manifesteDepuisRelease(source, baseURL string, attestations bool) (map[string]manifeste.Cible, map[string]string, error) {
	dossier := source
	if info, err := os.Stat(source); err != nil || !info.IsDir() {
		dossier, err = os.MkdirTemp("", "tordns-release-*")
		if err != nil {
			return nil, nil, err
		}
		defer os.RemoveAll(dossier)
		if err := telechargerRelease(source, dossier); err != nil {
			return nil, nil, err
		}
	}
	if baseURL == "" {
		baseURL = "https://github.com/garybourbier/tordns/releases/download/" + source
	}
	baseURL = strings.TrimRight(baseURL, "/")
	sommes, err := lireSommes(filepath.Join(dossier, "SHA256SUMS"))
	if err != nil {
		return nil, nil, err
	}
	var gh string
	if attestations {
		gh, err = exec.LookPath("gh")
		if err != nil {
			return nil, nil, errors.New("gh requis pour vérifier les attestations")
		}
	}
	cibles := map[string]manifeste.Cible{}
	for nom, somme := range sommes {
		if nom == "SHA256SUMS" || nom == "images.txt" || strings.HasSuffix(nom, ".sig") {
			continue
		}
		chemin := filepath.Join(dossier, nom)
		if err := verifierSomme(chemin, somme); err != nil {
			return nil, nil, err
		}
		if attestations {
			if err := verifierAttestation(gh, chemin); err != nil {
				return nil, nil, err
			}
		}
		info, err := os.Stat(chemin)
		if err != nil {
			return nil, nil, err
		}
		cible := nomCible(nom)
		if cible == "" {
			continue
		}
		if _, doublon := cibles[cible]; doublon {
			return nil, nil, fmt.Errorf("deux fichiers pour la cible %s", cible)
		}
		cibles[cible] = manifeste.Cible{
			URL:    baseURL + "/" + nom,
			Taille: info.Size(),
			SHA256: somme,
		}
	}
	if len(cibles) == 0 {
		return nil, nil, errors.New("aucune cible reconnue dans la release")
	}
	images, err := lireImages(filepath.Join(dossier, "images.txt"))
	if err != nil {
		return nil, nil, err
	}
	return cibles, images, nil
}
