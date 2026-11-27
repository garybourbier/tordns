package relais

// Mission 28, point 4 : cas de conformité communs aux trois validateurs.
//
// Le fichier `testvectors/dnssec_vectors.json` dit, pour chaque cas, le verdict
// attendu sur chaque plateforme. Ce test exécute le cas avec les fixtures du
// client Linux et compare le verdict observé. Il échoue aussi si le fichier
// annonce un cas que ce client ne sait pas produire (ou l'inverse), pour qu'un
// cas ajouté pour Windows ou Android ne passe pas silencieusement inaperçu ici.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
)

const fichierVecteurs = "../../testvectors/dnssec_vectors.json"

type vecteurCommun struct {
	Nom             string            `json:"name"`
	Description     string            `json:"description"`
	ExpectedVerdict string            `json:"expected_verdict"`
	Plateformes     map[string]string `json:"plateformes"`
}

type fichierVecteursJSON struct {
	Version json.RawMessage `json:"version"`
	Vectors []vecteurCommun `json:"vectors"`
}

func lireVecteurs(t *testing.T) []vecteurCommun {
	t.Helper()
	chemin, err := filepath.Abs(fichierVecteurs)
	if err != nil {
		t.Fatalf("chemin des vecteurs : %v", err)
	}
	brut, err := os.ReadFile(chemin)
	if err != nil {
		t.Fatalf("lecture de %s : %v", chemin, err)
	}
	var f fichierVecteursJSON
	if err := json.Unmarshal(brut, &f); err != nil {
		t.Fatalf("JSON invalide dans %s : %v", chemin, err)
	}
	if len(f.Vectors) == 0 {
		t.Fatal("aucun vecteur dans le fichier commun")
	}
	return f.Vectors
}

// verdict classe un résultat de validation avec le vocabulaire du fichier commun.
func verdict(err error) string {
	switch {
	case err == nil:
		return "accept"
	case errors.Is(err, ErrZoneNonSignee):
		return "accept_unsigned"
	default:
		return "reject"
	}
}

// casLinux associe chaque nom de cas à une fixture qui le produit réellement.
// Un cas absent de cette table ne doit pas être annoncé applicable à Linux.
func casLinux(t *testing.T, nom string) (func() error, bool) {
	preparer := func(configurer func(f *fauxResolveur), question string) func() error {
		return func() error {
			f, _ := chaineDeTest(t)
			configurer(f)
			return validerReponse(t, f, question)
		}
	}
	cas := map[string]func() error{
		"signed_zone_valid": preparer(func(*fauxResolveur) {}, "example.test"),
		"unsigned_zone_nsec_proves_no_ds": preparer(func(f *fauxResolveur) {
			f.sansDS = true
		}, "example.test"),
		"unsigned_zone_nsec3_opt_out": preparer(func(f *fauxResolveur) {
			f.mode = "nsec3-optout"
		}, "www.unsigned.example.test"),
		"forged_address_in_signed_zone": preparer(func(f *fauxResolveur) {
			f.altererA = true
		}, "example.test"),
		"missing_signature_on_signed_zone": preparer(func(f *fauxResolveur) {
			f.injecterA = true
		}, "www.example.test"),
		"expired_signature": preparer(func(f *fauxResolveur) {
			f.signatureA = func(rrset []dns.RR) *dns.RRSIG {
				return signerEntre(f.exemple, rrset,
					time.Now().Add(-60*24*time.Hour), time.Now().Add(-30*24*time.Hour))
			}
		}, "www.example.test"),
		"signature_by_wrong_zone": preparer(func(f *fauxResolveur) {
			f.signatureA = func(rrset []dns.RR) *dns.RRSIG { return signer(f.exemple, rrset) }
		}, "victime.test"),
		"nxdomain_with_nsec_proof": preparer(func(f *fauxResolveur) {
			f.mode = "nsec"
		}, "absent.example.test"),
		"nodata_with_nsec_proof": preparer(func(f *fauxResolveur) {
			f.mode = "nsec"
		}, "present.example.test"),
	}
	fixture, ok := cas[nom]
	return fixture, ok
}

func TestDNSSECVecteursCommuns(t *testing.T) {
	vecteurs := lireVecteurs(t)
	vus := make(map[string]bool, len(vecteurs))
	for _, v := range vecteurs {
		vus[v.Nom] = true
		attendu, declare := v.Plateformes["linux"]
		if !declare {
			t.Fatalf("cas %q : aucun verdict déclaré pour Linux", v.Nom)
		}
		fixture, connu := casLinux(t, v.Nom)
		switch {
		case attendu == "n/a" && connu:
			t.Errorf("cas %q : déclaré non applicable à Linux mais une fixture existe", v.Nom)
			continue
		case attendu != "n/a" && !connu:
			t.Errorf("cas %q : déclaré applicable à Linux mais aucune fixture ne le produit", v.Nom)
			continue
		case attendu == "n/a":
			continue
		}
		obtenu := verdict(fixture())
		if obtenu != attendu {
			t.Errorf("cas %q (%s) : verdict Linux %q, attendu %q", v.Nom, v.Description, obtenu, attendu)
		}
	}
	if _, connu := casLinux(t, "signed_zone_valid"); !connu {
		t.Fatal("fixture de référence absente")
	}
	for nom := range map[string]struct{}{
		"signed_zone_valid": {}, "unsigned_zone_nsec_proves_no_ds": {},
		"unsigned_zone_nsec3_opt_out": {}, "forged_address_in_signed_zone": {},
		"missing_signature_on_signed_zone": {}, "expired_signature": {},
		"signature_by_wrong_zone": {}, "nxdomain_with_nsec_proof": {},
		"nodata_with_nsec_proof": {},
	} {
		if !vus[nom] {
			t.Errorf("fixture %q sans cas correspondant dans %s", nom, fichierVecteurs)
		}
	}
}
