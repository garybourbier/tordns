// Validation d'un nom réel pour le diagnostic (mission 28, point 5).
//
// `ValiderNom` interroge une seule question (A, bit DO posé) via le transport
// fourni, puis applique la même chaîne DNSSEC que le relais : ancres IANA
// épinglées, DS/DNSKEY, puis RRSIG de la réponse. Le transport n'est pas
// validé ici : c'est à l'appelant de fournir un canal dont il accepte la
// provenance (le diagnostic le documente). Aucun nom n'est journalisé.

package relais

import (
	"fmt"

	"github.com/miekg/dns"
)

// ValiderNom valide DNSSEC la réponse A de nom, avec les ancres racine
// compilées. Retourne ErrZoneNonSignee pour une délégation sans DS (le mode
// auto l'accepte, le mode strict la refuse) et une erreur pour toute chaîne
// rompue, signature fausse ou réponse mal formée.
func ValiderNom(nom string, interroger func([]byte) ([]byte, error)) error {
	if _, ok := dns.IsDomainName(nom); !ok || nom == "" {
		return fmt.Errorf("nom à valider invalide : %q", nom)
	}
	v, err := nouveauValidateur(interroger, ancreRacineDS)
	if err != nil {
		return err
	}
	requete := new(dns.Msg)
	requete.SetQuestion(dns.Fqdn(nom), dns.TypeA)
	// Le bit DO exige les signatures et les preuves de négation ; sans lui,
	// un résolveur peut retirer les RRSIG et la validation échouerait à tort.
	requete.SetEdns0(4096, true)
	paquet, err := requete.Pack()
	if err != nil {
		return fmt.Errorf("requête DNS : %w", err)
	}
	reponse, err := interroger(paquet)
	if err != nil {
		return err
	}
	if err := v.Valider(reponse); err != nil {
		return err
	}
	return nil
}
