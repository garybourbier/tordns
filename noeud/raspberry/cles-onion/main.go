// TorDNS — génération de l'identité d'un service caché v3 (Mission 24).
//
// Le premier démarrage d'une carte doit créer les clés .onion sur la carte,
// jamais dans l'image. Ce programme écrit les deux fichiers de clés que Tor
// attend dans un dossier de service caché (format `hs_ed25519_*` du rend
// spec v3) et refuse d'écraser une identité existante.
//
// L'adresse .onion n'est délibérément pas calculée ici : c'est Tor qui écrit
// `hostname` à son premier démarrage, à partir de ces mêmes clés. Une seule
// implémentation du format, donc une seule façon de se tromper.
//
// Aucun secret ne sort du dossier : rien n'est envoyé, rien n'est journalisé.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

const (
	// Tor préfixe les deux fichiers du rend spec v3 par ces 35 octets.
	prefixeSecret = "== ed25519v1-secret: type0 ==\x00\x00\x00"
	prefixePublic = "== ed25519v1-public: type0 ==\x00\x00\x00"
)

// generer rend la clé publique (32 octets) et la clé secrète étendue
// (64 octets) au format de Tor : le scalaire a clampé et le préfixe, tirés
// tous deux de SHA-512 de la graine. Ce n'est pas la forme « graine ‖ clé
// publique » de Go, que Tor refuserait.
func generer() ([]byte, []byte, error) {
	graine := make([]byte, 32)
	if _, err := rand.Read(graine); err != nil {
		return nil, nil, err
	}
	h := sha512.Sum512(graine)
	etendue := h[:]
	etendue[0] &= 248
	etendue[31] &= 127
	etendue[31] |= 64

	pub := ed25519.NewKeyFromSeed(graine).Public().(ed25519.PublicKey)
	return pub, append([]byte(nil), etendue...), nil
}

// ecrire crée l'identité dans dossier ; refuse un dossier qui en contient
// déjà une (les clés d'un nœud ne se régénèrent jamais par accident).
func ecrire(dossier string, pub, priv []byte) error {
	secret := filepath.Join(dossier, "hs_ed25519_secret_key")
	public := filepath.Join(dossier, "hs_ed25519_public_key")

	for _, f := range []string{secret, public} {
		if _, err := os.Lstat(f); err == nil {
			return fmt.Errorf("%s existe déjà : identité conservée", f)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := os.MkdirAll(dossier, 0o700); err != nil {
		return err
	}

	if err := os.WriteFile(secret, append([]byte(prefixeSecret), priv...), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(public, append([]byte(prefixePublic), pub...), 0o644); err != nil {
		return err
	}
	return nil
}

func main() {
	dossier := flag.String("dossier", "", "dossier du service caché (créé au besoin)")
	flag.Parse()

	if *dossier == "" {
		fmt.Fprintln(os.Stderr, "usage : cles-onion -dossier <dossier du service caché>")
		os.Exit(2)
	}

	pub, priv, err := generer()
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERREUR : génération impossible : %v\n", err)
		os.Exit(1)
	}
	if err := ecrire(*dossier, pub, priv); err != nil {
		fmt.Fprintf(os.Stderr, "ERREUR : %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("clés écrites dans %s\n", *dossier)
}
