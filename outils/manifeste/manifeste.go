// TorDNS — manifeste de publication signé (Mission 11).
//
// Un manifeste décrit une version publiée : les fichiers à télécharger (URL,
// taille, SHA-256), les empreintes des images Docker des nœuds, et les
// adresses .onion publiques. Il est signé en Ed25519 : la signature porte sur
// les octets exacts du fichier JSON, sans re-sérialisation.
//
// Aucune dépendance hors bibliothèque standard : la vérification doit pouvoir
// tourner hors ligne, sur un nœud comme sur un poste de publication.
package manifeste

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"time"
)

// ClePubliqueEpinglee est la clé Ed25519 de publication compilée dans les
// programmes. C'est une clé de test, dont la clé privée n'a pas été conservée :
// elle ne peut rien signer. La clé réelle de Gary se substitue par
// -ldflags "-X tordns/manifeste.ClePubliqueEpinglee=<hex>" au moment de la
// construction (voir outils/publier/README.md, rotation comprise).
var ClePubliqueEpinglee = "3b6ed1b0c0d0f7a05b1a5c3f1bb1a0b1b1b0c0d0e0f00112233445566778899a"

// TailleMaxManifeste borne la lecture d'un manifeste (un Ko suffit largement).
const TailleMaxManifeste = 64 << 10

// Cible décrit un fichier publié pour une plateforme.
type Cible struct {
	URL    string `json:"url"`
	Taille int64  `json:"taille"`
	SHA256 string `json:"sha256"`
}

// Manifeste est le contenu signé. Les clés JSON sont stables : le fichier est
// signé tel quel, les outils ne le réécrivent jamais après signature.
type Manifeste struct {
	Version     int64            `json:"version"`
	Expire      string           `json:"expire"`
	Cibles      map[string]Cible `json:"cibles"`
	Images      map[string]string `json:"images,omitempty"`
	Adresses    map[string]string `json:"adresses,omitempty"`
	CleSuivante string           `json:"cle_suivante,omitempty"`
}

var (
	reSHA256 = regexp.MustCompile(`^[0-9a-f]{64}$`)
	reImage  = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._/:-]*@sha256:[0-9a-f]{64}$`)
	reOnion  = regexp.MustCompile(`^[a-z2-7]{56}\.onion$`)
	reHex64  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// ErreurRefus porte la raison précise d'un refus : l'appelant la journalise
// sans jamais appliquer la mise à jour.
type ErreurRefus struct{ Raison string }

func (e *ErreurRefus) Error() string { return e.Raison }

func refus(format string, args ...any) error {
	return &ErreurRefus{Raison: fmt.Sprintf(format, args...)}
}

// Verifier contrôle la signature puis la validité du manifeste. maintenant
// est injectable pour les tests ; dans un service, passer time.Now().
func Verifier(brut, signature []byte, clePublique string, maintenant time.Time) (*Manifeste, error) {
	cle, err := hex.DecodeString(clePublique)
	if err != nil || len(cle) != ed25519.PublicKeySize {
		return nil, refus("clé publique de publication invalide")
	}
	if len(signature) != ed25519.SignatureSize {
		return nil, refus("signature de taille invalide (%d octets)", len(signature))
	}
	if !ed25519.Verify(ed25519.PublicKey(cle), brut, signature) {
		return nil, refus("signature invalide")
	}
	var m Manifeste
	if err := json.Unmarshal(brut, &m); err != nil {
		return nil, refus("manifeste illisible : %v", err)
	}
	if m.Version < 1 {
		return nil, refus("version absente ou nulle")
	}
	expire, err := time.Parse(time.RFC3339, m.Expire)
	if err != nil {
		return nil, refus("date d'expiration invalide : %q", m.Expire)
	}
	if !expire.After(maintenant) {
		return nil, refus("manifeste expiré depuis %s", expire.UTC().Format(time.RFC3339))
	}
	if len(m.Cibles) == 0 {
		return nil, refus("aucune cible")
	}
	for nom, c := range m.Cibles {
		u, err := url.Parse(c.URL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return nil, refus("cible %q : URL invalide %q", nom, c.URL)
		}
		if c.Taille < 1 {
			return nil, refus("cible %q : taille invalide", nom)
		}
		if !reSHA256.MatchString(c.SHA256) {
			return nil, refus("cible %q : SHA-256 invalide", nom)
		}
	}
	for nom, image := range m.Images {
		// Une étiquette peut être réécrite par le registre ; seule une
		// référence nom@sha256:… est acceptable.
		if !reImage.MatchString(image) {
			return nil, refus("image %q : référence nom@sha256:… attendue, reçu %q", nom, image)
		}
	}
	for nom, adresse := range m.Adresses {
		if !reOnion.MatchString(adresse) {
			return nil, refus("adresse %q invalide", nom)
		}
	}
	if m.CleSuivante != "" && !reHex64.MatchString(m.CleSuivante) {
		return nil, refus("clé suivante invalide")
	}
	return &m, nil
}

// Accepter exige en plus une version strictement supérieure à celle installée :
// un rejeu d'ancien manifeste, même parfaitement signé, est refusé.
func Accepter(brut, signature []byte, clePublique string, versionInstallee int64, maintenant time.Time) (*Manifeste, error) {
	m, err := Verifier(brut, signature, clePublique, maintenant)
	if err != nil {
		return nil, err
	}
	if m.Version <= versionInstallee {
		return nil, refus("version %d déjà installée (ou inférieure)", m.Version)
	}
	return m, nil
}

// LireManifeste lit le couple manifeste/signature depuis le disque.
func LireManifeste(chemin, cheminSignature string) ([]byte, []byte, error) {
	brut, err := os.ReadFile(chemin)
	if err != nil {
		return nil, nil, err
	}
	if len(brut) > TailleMaxManifeste {
		return nil, nil, errors.New("manifeste trop gros")
	}
	signature, err := os.ReadFile(cheminSignature)
	if err != nil {
		return nil, nil, err
	}
	return brut, signature, nil
}

// VerifierFichiers contrôle hors ligne qu'un couple de fichiers est signé.
func VerifierFichiers(chemin, cheminSignature, clePublique string, maintenant time.Time) (*Manifeste, error) {
	brut, signature, err := LireManifeste(chemin, cheminSignature)
	if err != nil {
		return nil, err
	}
	return Verifier(brut, signature, clePublique, maintenant)
}
