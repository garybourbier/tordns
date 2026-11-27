package relais

import (
	"errors"
	"testing"

	"github.com/miekg/dns"
)

// Le diagnostic doit poser le bit DO et demander A : sans DO, les RRSIG
// peuvent être retirés par le résolveur et la validation échouerait à tort.
func TestValiderNomPoseDOEtDemandeA(t *testing.T) {
	var vue *dns.Msg
	interroger := func(paquet []byte) ([]byte, error) {
		var m dns.Msg
		if err := m.Unpack(paquet); err != nil {
			t.Fatalf("requête illisible : %v", err)
		}
		vue = &m
		return nil, errors.New("transport simulé")
	}
	err := ValiderNom("exemple.test", interroger)
	if err == nil || err.Error() != "transport simulé" {
		t.Fatalf("erreur de transport non propagée : %v", err)
	}
	if vue == nil || len(vue.Question) != 1 {
		t.Fatalf("question absente : %+v", vue)
	}
	q := vue.Question[0]
	if q.Name != "exemple.test." || q.Qtype != dns.TypeA {
		t.Fatalf("question %s/%d, attendu exemple.test./A", q.Name, q.Qtype)
	}
	opt := vue.IsEdns0()
	if opt == nil || !opt.Do() {
		t.Fatalf("bit DO absent de la requête du diagnostic")
	}
}

func TestValiderNomRefuseNomInvalide(t *testing.T) {
	appele := false
	err := ValiderNom("nom..invalide", func([]byte) ([]byte, error) {
		appele = true
		return nil, nil
	})
	if err == nil {
		t.Fatal("nom invalide accepté")
	}
	if appele {
		t.Fatal("le transport a été appelé pour un nom invalide")
	}
}
