// Validation DNSSEC côté client (mission 12).
//
// Le client ne fait plus confiance au bit AD du nœud : il reconstruit la
// chaîne d'ancrage depuis la clé racine épinglée, valide les DS et DNSKEY de
// chaque zone, puis la signature de la réponse. Toute la cryptographie est
// celle de github.com/miekg/dns (RRSIG.Verify), pas une implémentation maison.
//
// Une zone non signée est acceptée en mode « auto » (comportement normal
// d'Internet) et refusée en mode « strict ». Les preuves de négation NSEC/NSEC3
// ne sont pas encore validées : une réponse négative signée est contrôlée pour
// sa signature, mais l'absence de DS n'est pas prouvée cryptographiquement.

package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

// Racine DNSSEC : clé 20326 (KSK 2017), algorithme 8, empreinte SHA-256.
// Ce n'est pas un secret ; c'est l'ancre publique de l'IANA.
const ancreRacineDS = "20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"

// ErrZoneNonSignee indique une délégation sans DS (zone non signée). Le mode
// auto l'accepte, le mode strict la refuse.
var ErrZoneNonSignee = errors.New("zone non signée")

type validateurDNSSEC struct {
	// interroger envoie une requête DNS brute au nœud, sans repasser par la
	// validation (sinon la chaîne se validerait elle-même à l'infini).
	interroger func([]byte) ([]byte, error)
	ancre      *dns.DS
}

func nouveauValidateur(interroger func([]byte) ([]byte, error), ancre string) (*validateurDNSSEC, error) {
	rr, err := dns.NewRR(". IN DS " + ancre)
	if err != nil {
		return nil, fmt.Errorf("ancre DNSSEC invalide : %w", err)
	}
	ds, ok := rr.(*dns.DS)
	if !ok {
		return nil, errors.New("ancre DNSSEC : enregistrement DS attendu")
	}
	return &validateurDNSSEC{interroger: interroger, ancre: ds}, nil
}

// Valider vérifie la réponse complète. Retourne ErrZoneNonSignee si la chaîne
// s'arrête sur une délégation sans DS.
func (v *validateurDNSSEC) Valider(reponse []byte) error {
	var m dns.Msg
	if err := m.Unpack(reponse); err != nil {
		return fmt.Errorf("réponse DNS illisible : %w", err)
	}
	if len(m.Question) != 1 {
		return errors.New("réponse sans question unique")
	}
	q := m.Question[0]

	cles, err := v.cleZone(".", v.ancre)
	if err != nil {
		return err
	}
	zone := "."
	nom := strings.TrimSuffix(strings.ToLower(q.Name), ".")
	etiquettes := []string{}
	if nom != "" {
		etiquettes = strings.Split(nom, ".")
	}
	for i := len(etiquettes) - 1; i >= 0; i-- {
		enfant := etiquettes[i] + "." + zone
		if zone == "." {
			enfant = etiquettes[i] + "."
		}
		ds, err := v.dsDe(enfant, cles)
		if errors.Is(err, ErrZoneNonSignee) {
			return ErrZoneNonSignee
		}
		if err != nil {
			return err
		}
		cles, err = v.cleZone(enfant, ds)
		if err != nil {
			return err
		}
		zone = enfant
	}

	// Valide chaque RRset de la réponse avec les clés de sa zone signataire.
	// On exige au moins une signature valide pour le type demandé.
	valide := false
	for _, sig := range signatures(m.Answer) {
		rrset := rrset(m.Answer, sig.Hdr.Name, sig.TypeCovered)
		if len(rrset) == 0 {
			continue
		}
		if err := v.verifierSignature(sig, rrset, cles); err != nil {
			return err
		}
		if sig.TypeCovered == q.Qtype || sig.TypeCovered == dns.TypeCNAME {
			valide = true
		}
	}
	if !valide {
		// Réponse négative : les NSEC/NSEC3 signés sont vérifiés comme tout
		// autre RRset, sans prétendre prouver l'absence.
		negatif := false
		for _, sig := range append(signatures(m.Answer), signatures(m.Ns)...) {
			if sig.TypeCovered != dns.TypeNSEC && sig.TypeCovered != dns.TypeNSEC3 {
				continue
			}
			rrset := append(rrset(m.Answer, sig.Hdr.Name, sig.TypeCovered),
				rrset(m.Ns, sig.Hdr.Name, sig.TypeCovered)...)
			if len(rrset) == 0 {
				continue
			}
			if err := v.verifierSignature(sig, rrset, cles); err != nil {
				return err
			}
			negatif = true
		}
		if !negatif {
			return fmt.Errorf("réponse sans signature DNSSEC valide pour le type %d", q.Qtype)
		}
	}
	return nil
}

func (v *validateurDNSSEC) dsDe(zone string, parent []*dns.DNSKEY) (*dns.DS, error) {
	rep, err := v.interroger(requete(zone, dns.TypeDS))
	if err != nil {
		return nil, fmt.Errorf("DS de %s : %w", zone, err)
	}
	var m dns.Msg
	if err := m.Unpack(rep); err != nil {
		return nil, fmt.Errorf("DS de %s illisible : %w", zone, err)
	}
	var ds *dns.DS
	var sig *dns.RRSIG
	for _, rr := range m.Answer {
		switch r := rr.(type) {
		case *dns.DS:
			ds = r
		case *dns.RRSIG:
			if r.TypeCovered == dns.TypeDS {
				sig = r
			}
		}
	}
	if ds == nil {
		if len(m.Answer) == 0 && (m.Rcode == dns.RcodeSuccess || m.Rcode == dns.RcodeNameError) {
			return nil, ErrZoneNonSignee
		}
		return nil, fmt.Errorf("DS de %s absent", zone)
	}
	if sig == nil {
		return nil, fmt.Errorf("DS de %s non signé", zone)
	}
	if err := v.verifierSignature(sig, rrset(m.Answer, ds.Hdr.Name, dns.TypeDS), parent); err != nil {
		return nil, fmt.Errorf("DS de %s : %w", zone, err)
	}
	return ds, nil
}

func (v *validateurDNSSEC) cleZone(zone string, ds *dns.DS) ([]*dns.DNSKEY, error) {
	rep, err := v.interroger(requete(zone, dns.TypeDNSKEY))
	if err != nil {
		return nil, fmt.Errorf("DNSKEY de %s : %w", zone, err)
	}
	var m dns.Msg
	if err := m.Unpack(rep); err != nil {
		return nil, fmt.Errorf("DNSKEY de %s illisible : %w", zone, err)
	}
	var rrset []dns.RR
	var cles []*dns.DNSKEY
	var sigs []*dns.RRSIG
	for _, rr := range m.Answer {
		switch r := rr.(type) {
		case *dns.DNSKEY:
			rrset = append(rrset, r)
			if correspondDS(r, ds) {
				cles = append(cles, r)
			}
		case *dns.RRSIG:
			if r.TypeCovered == dns.TypeDNSKEY {
				sigs = append(sigs, r)
			}
		}
	}
	if len(cles) == 0 {
		return nil, fmt.Errorf("aucune DNSKEY de %s ne correspond au DS", zone)
	}
	for _, sig := range sigs {
		for _, cle := range cles {
			if err := sig.Verify(cle, rrset); err == nil {
				// Toutes les DNSKEY de la zone sont utilisables pour signer
				// les réponses une fois le RRset DNSKEY authentifié.
				var toutes []*dns.DNSKEY
				for _, rr := range rrset {
					if k, ok := rr.(*dns.DNSKEY); ok {
						toutes = append(toutes, k)
					}
				}
				return toutes, nil
			}
		}
	}
	return nil, fmt.Errorf("DNSKEY de %s non signé par le DS", zone)
}

func (v *validateurDNSSEC) verifierSignature(sig *dns.RRSIG, rrset []dns.RR, cles []*dns.DNSKEY) error {
	for _, cle := range cles {
		if cle.KeyTag() != sig.KeyTag || cle.Algorithm != sig.Algorithm {
			continue
		}
		if err := sig.Verify(cle, rrset); err == nil {
			return nil
		}
	}
	return fmt.Errorf("signature %s/%d invalide", sig.Hdr.Name, sig.TypeCovered)
}

func correspondDS(cle *dns.DNSKEY, ds *dns.DS) bool {
	if ds == nil || cle.Algorithm != ds.Algorithm || cle.KeyTag() != ds.KeyTag {
		return false
	}
	calculee := cle.ToDS(ds.DigestType)
	return calculee != nil && strings.EqualFold(calculee.Digest, ds.Digest)
}

func signatures(rrs []dns.RR) []*dns.RRSIG {
	var out []*dns.RRSIG
	for _, rr := range rrs {
		if s, ok := rr.(*dns.RRSIG); ok {
			out = append(out, s)
		}
	}
	return out
}

func rrset(rrs []dns.RR, nom string, typ uint16) []dns.RR {
	var out []dns.RR
	for _, rr := range rrs {
		h := rr.Header()
		if h.Rrtype == typ && strings.EqualFold(h.Name, nom) &&
			(h.Class == dns.ClassINET || h.Class == dns.ClassNONE) {
			out = append(out, rr)
		}
	}
	return out
}

func requete(nom string, typ uint16) []byte {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(nom), typ)
	m.SetEdns0(1232, true) // DO : demander les signatures
	m.RecursionDesired = true
	brut, _ := m.Pack()
	return brut
}
