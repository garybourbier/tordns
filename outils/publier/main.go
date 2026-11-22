// tordns-signer — publication signée de TorDNS (Mission 11).
//
//	tordns-signer cle --dossier <hors dépôt>
//	tordns-signer manifeste --dossier <clés> --version 2 --sortie <dossier> \
//	    --cible noeud=./noeud.tar.gz,https://…/maj/noeud.tar.gz \
//	    --image unbound=sha256:… --adresse coeur=….onion
//	tordns-signer verifier --manifeste … --signature … [--version-installee 1]
//
// Aucune connexion réseau : l'outil ne fait que signer et vérifier des
// fichiers locaux.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"tordns/manifeste"
)

type liste []string

func (l *liste) String() string { return strings.Join(*l, ",") }
func (l *liste) Set(v string) error {
	*l = append(*l, v)
	return nil
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "cle":
		err = commandeCle(os.Args[2:])
	case "manifeste":
		err = commandeManifeste(os.Args[2:])
	case "verifier":
		err = commandeVerifier(os.Args[2:])
	case "-h", "--help", "aide":
		usage()
		return
	default:
		err = fmt.Errorf("commande inconnue : %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERREUR : %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `Usage : tordns-signer <commande> [options]

  cle        crée une paire Ed25519 de publication dans un dossier choisi
  manifeste  construit et signe manifeste.json (+ .sig)
  verifier   vérifie hors ligne un manifeste signé

"tordns-signer <commande> -h" pour les options de chaque commande.
`)
}

func commandeCle(args []string) error {
	fs := flag.NewFlagSet("cle", flag.ExitOnError)
	dossier := fs.String("dossier", "", "dossier de la clé, hors du dépôt (obligatoire)")
	forcer := fs.Bool("forcer", false, "remplace une clé existante (rotation)")
	fs.Parse(args)
	if *dossier == "" {
		return errors.New("--dossier obligatoire")
	}
	if err := os.MkdirAll(*dossier, 0o700); err != nil {
		return err
	}
	cheminPrivee := filepath.Join(*dossier, "publication.key")
	cheminPublique := filepath.Join(*dossier, "publication.pub")
	if !*forcer {
		if _, err := os.Stat(cheminPrivee); err == nil {
			return fmt.Errorf("clé déjà présente dans %s (utiliser --forcer pour une rotation)", *dossier)
		}
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := os.WriteFile(cheminPrivee, []byte(hex.EncodeToString(priv.Seed())+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(cheminPublique, []byte(hex.EncodeToString(pub)+"\n"), 0o644); err != nil {
		return err
	}
	fmt.Printf("Clé de publication créée dans %s (privée 0600, publique 0644).\n", *dossier)
	fmt.Printf("Clé publique : %s\n", hex.EncodeToString(pub))
	fmt.Println("Conserver la clé privée hors ligne, jamais dans le dépôt ; compiler la publique avec -ldflags.")
	return nil
}

func chargerPrivee(dossier string) (ed25519.PrivateKey, error) {
	brut, err := os.ReadFile(filepath.Join(dossier, "publication.key"))
	if err != nil {
		return nil, err
	}
	graine, err := hex.DecodeString(strings.TrimSpace(string(brut)))
	if err != nil || len(graine) != ed25519.SeedSize {
		return nil, errors.New("clé privée invalide (graine Ed25519 de 32 octets en hexadécimal attendue)")
	}
	return ed25519.NewKeyFromSeed(graine), nil
}

func commandeManifeste(args []string) error {
	fs := flag.NewFlagSet("manifeste", flag.ExitOnError)
	dossier := fs.String("dossier", "", "dossier contenant publication.key (obligatoire)")
	sortie := fs.String("sortie", ".", "dossier où écrire manifeste.json et sa signature")
	version := fs.Int64("version", 0, "version entière croissante (obligatoire)")
	expiration := fs.String("expire", "", "date d'expiration RFC 3339 (défaut : dans 30 jours)")
	var cibles liste
	var images liste
	var adresses liste
	cleSuivante := fs.String("cle-suivante", "", "clé publique annoncée pour la rotation suivante")
	fs.Var(&cibles, "cible", "nom=chemin,url : fichier local et URL publiée (répétable)")
	fs.Var(&images, "image", "nom=sha256:… : empreinte d'image Docker (répétable)")
	fs.Var(&adresses, "adresse", "nom=….onion : adresse publique (répétable)")
	fs.Parse(args)

	if *dossier == "" {
		return errors.New("--dossier obligatoire")
	}
	if *version < 1 {
		return errors.New("--version doit être un entier positif")
	}
	var expire time.Time
	if *expiration == "" {
		expire = time.Now().UTC().Add(30 * 24 * time.Hour).Truncate(time.Second)
	} else {
		var err error
		expire, err = time.Parse(time.RFC3339, *expiration)
		if err != nil {
			return fmt.Errorf("--expire doit être une date RFC 3339 : %w", err)
		}
	}

	m := manifeste.Manifeste{
		Version:     *version,
		Expire:      expire.UTC().Format(time.RFC3339),
		Cibles:      map[string]manifeste.Cible{},
		Images:      map[string]string{},
		Adresses:    map[string]string{},
		CleSuivante: strings.TrimSpace(*cleSuivante),
	}
	for _, spec := range cibles {
		nom, chemin, url, err := decouperCible(spec)
		if err != nil {
			return err
		}
		taille, somme, err := empreinteFichier(chemin)
		if err != nil {
			return err
		}
		m.Cibles[nom] = manifeste.Cible{URL: url, Taille: taille, SHA256: somme}
	}
	for _, spec := range images {
		nom, valeur, ok := strings.Cut(spec, "=")
		if !ok || nom == "" {
			return fmt.Errorf("--image attend nom=sha256:… : %q", spec)
		}
		m.Images[nom] = valeur
	}
	for _, spec := range adresses {
		nom, valeur, ok := strings.Cut(spec, "=")
		if !ok || nom == "" {
			return fmt.Errorf("--adresse attend nom=….onion : %q", spec)
		}
		m.Adresses[nom] = valeur
	}

	brut, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	brut = append(brut, '\n')
	priv, err := chargerPrivee(*dossier)
	if err != nil {
		return err
	}
	signature := ed25519.Sign(priv, brut)
	if err := os.MkdirAll(*sortie, 0o755); err != nil {
		return err
	}
	cheminManifeste := filepath.Join(*sortie, "manifeste.json")
	cheminSignature := filepath.Join(*sortie, "manifeste.json.sig")
	if err := os.WriteFile(cheminManifeste, brut, 0o644); err != nil {
		return err
	}
	// La signature est binaire : le fichier .sig contient 64 octets bruts.
	if err := os.WriteFile(cheminSignature, signature, 0o644); err != nil {
		return err
	}
	// Vérification immédiate avec la clé publique correspondante.
	pub := priv.Public().(ed25519.PublicKey)
	if _, err := manifeste.Verifier(brut, signature, hex.EncodeToString(pub), time.Now()); err != nil {
		return fmt.Errorf("le manifeste signé ne se vérifie pas : %w", err)
	}
	fmt.Printf("Manifeste v%d signé : %s (+ %s)\n", m.Version, cheminManifeste, filepath.Base(cheminSignature))
	fmt.Printf("Clé publique : %s\n", hex.EncodeToString(pub))
	return nil
}

func decouperCible(spec string) (nom, chemin, url string, err error) {
	nom, reste, ok := strings.Cut(spec, "=")
	if !ok || nom == "" {
		return "", "", "", fmt.Errorf("--cible attend nom=chemin,url : %q", spec)
	}
	chemin, url, ok = strings.Cut(reste, ",")
	if !ok || chemin == "" || url == "" {
		return "", "", "", fmt.Errorf("--cible attend nom=chemin,url : %q", spec)
	}
	return nom, chemin, url, nil
}

func empreinteFichier(chemin string) (int64, string, error) {
	f, err := os.Open(chemin)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()
	h := sha256.New()
	taille, err := io.Copy(h, f)
	if err != nil {
		return 0, "", err
	}
	return taille, hex.EncodeToString(h.Sum(nil)), nil
}

func commandeVerifier(args []string) error {
	fs := flag.NewFlagSet("verifier", flag.ExitOnError)
	chemin := fs.String("manifeste", "manifeste.json", "fichier manifeste")
	signature := fs.String("signature", "manifeste.json.sig", "fichier de signature")
	cle := fs.String("cle", manifeste.ClePubliqueEpinglee, "clé publique hexadécimale")
	installee := fs.Int64("version-installee", 0, "version actuellement installée")
	maintenantTexte := fs.String("maintenant", "", "horloge de test RFC 3339 (défaut : maintenant)")
	fs.Parse(args)

	maintenant := time.Now()
	if *maintenantTexte != "" {
		var err error
		maintenant, err = time.Parse(time.RFC3339, *maintenantTexte)
		if err != nil {
			return err
		}
	}
	brut, sig, err := manifeste.LireManifeste(*chemin, *signature)
	if err != nil {
		return err
	}
	m, err := manifeste.Accepter(brut, sig, *cle, *installee, maintenant)
	if err != nil {
		return err
	}
	fmt.Printf("OK : manifeste v%d valide, expire le %s.\n", m.Version, m.Expire)
	for nom, c := range m.Cibles {
		fmt.Printf("  cible %-24s %8d octets  sha256:%s…\n", nom, c.Taille, c.SHA256[:16])
	}
	for nom, image := range m.Images {
		fmt.Printf("  image %-24s %s\n", nom, image)
	}
	for nom, adresse := range m.Adresses {
		fmt.Printf("  adresse %-22s %s…\n", nom, adresse[:12])
	}
	if m.CleSuivante != "" {
		fmt.Printf("  rotation annoncée : %s…\n", m.CleSuivante[:16])
	}
	return nil
}
