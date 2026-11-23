// Validation DNSSEC côté client (mission 12).
//
// Le client ne fait plus confiance au bit AD du nœud : il reconstruit la
// chaîne d'ancrage depuis la clé racine épinglée, valide les DS et DNSKEY de
// chaque zone, puis la signature de la réponse. Toute la cryptographie est
// celle de github.com/miekg/dns (RRSIG.Verify), pas une implémentation maison.
//
// Une zone non signée est acceptée en mode « auto » (comportement normal
// d'Internet) et refusée en mode « strict ». Les preuves de négation NSEC et
// NSEC3 sont vérifiées : nom absent, wildcard absent, NODATA et délégation
// sans DS. Une preuve absente ou incohérente est refusée, jamais devinée.

package main

import (
	"errors"
	"fmt"
	"strings"
	"time"

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
	ancre      []*dns.DS
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
	return &validateurDNSSEC{interroger: interroger, ancre: []*dns.DS{ds}}, nil
}

// Valider vérifie la réponse complète. Retourne ErrZoneNonSignee si la chaîne
// s'arrête sur une délégation sans DS et que la réponse n'est pas signée.
func (v *validateurDNSSEC) Valider(reponse []byte) error {
	var m dns.Msg
	if err := m.Unpack(reponse); err != nil {
		return fmt.Errorf("réponse DNS illisible : %w", err)
	}
	if len(m.Question) != 1 {
		return errors.New("réponse sans question unique")
	}
	q := m.Question[0]

	// Réponse positive : chaque RRset de la section réponse doit être signé
	// par une zone ancrée. Un RRset non signé ajouté à côté d'un RRset valide
	// ne doit jamais atteindre le client.
	sigs := signatures(m.Answer)
	if len(sigs) == 0 {
		if len(signatures(m.Ns)) > 0 {
			return v.validerNegatif(q, &m)
		}
		return v.reponseSansSignature(q)
	}
	type cleRRset struct {
		nom string
		typ uint16
	}
	valides := make(map[cleRRset]bool)
	positif := false
	for _, sig := range sigs {
		rrs := rrset(m.Answer, sig.Hdr.Name, sig.TypeCovered)
		if len(rrs) == 0 {
			continue
		}
		cles, err := v.clesSignataire(sig.SignerName)
		if err != nil {
			return fmt.Errorf("signature %s/%d : %w", sig.Hdr.Name, sig.TypeCovered, err)
		}
		if err := v.verifierSignature(sig, rrs, cles); err != nil {
			return err
		}
		valides[cleRRset{canon(sig.Hdr.Name), sig.TypeCovered}] = true
		if sig.TypeCovered == q.Qtype || sig.TypeCovered == dns.TypeCNAME {
			positif = true
		}
	}
	for _, rr := range m.Answer {
		if _, ok := rr.(*dns.RRSIG); ok {
			continue
		}
		h := rr.Header()
		if valides[cleRRset{canon(h.Name), h.Rrtype}] {
			continue
		}
		// Une cible de CNAME peut se trouver dans une zone non signée.
		// Une donnée non signée ajoutée dans une zone signée, elle, est
		// refusée : elle ne doit jamais atteindre le client.
		_, _, insecure, err := v.parcourir(h.Name)
		if err != nil || !insecure {
			return fmt.Errorf("RRset non signé dans la réponse : %s/%d", h.Name, h.Rrtype)
		}
	}
	if positif {
		return nil
	}

	// Réponse négative : les NSEC/NSEC3 de la section autorité portent la
	// preuve. Leur signature et leur sémantique sont vérifiées ensemble.
	return v.validerNegatif(q, &m)
}

func (v *validateurDNSSEC) reponseSansSignature(q dns.Question) error {
	zone, _, insecure, err := v.parcourir(q.Name)
	if err != nil {
		return err
	}
	if insecure {
		return ErrZoneNonSignee
	}
	return fmt.Errorf("réponse sans signature DNSSEC (zone %s)", zone)
}

func (v *validateurDNSSEC) validerNegatif(q dns.Question, m *dns.Msg) error {
	if m.Rcode != dns.RcodeSuccess && m.Rcode != dns.RcodeNameError {
		return fmt.Errorf("réponse négative avec RCODE %d", m.Rcode)
	}
	tous := append(append([]dns.RR{}, m.Answer...), m.Ns...)
	var derniere error
	vus := make(map[string]bool)
	for _, sig := range signatures(tous) {
		if sig.TypeCovered != dns.TypeNSEC && sig.TypeCovered != dns.TypeNSEC3 {
			continue
		}
		signataire := canon(sig.SignerName)
		if vus[signataire] {
			continue
		}
		vus[signataire] = true
		cles, err := v.clesSignataire(signataire)
		if err != nil {
			derniere = err
			continue
		}
		if _, err := v.preuveAbsence(signataire, cles, q.Name, q.Qtype, m); err == nil {
			return nil
		} else {
			derniere = err
		}
	}
	if derniere != nil {
		return derniere
	}
	// Aucune preuve signée : distinguer une zone non signée d'une réponse
	// signée à laquelle on a retiré sa preuve.
	zone, _, insecure, err := v.parcourir(q.Name)
	if err != nil {
		return err
	}
	if insecure {
		return ErrZoneNonSignee
	}
	return fmt.Errorf("réponse négative sans preuve NSEC/NSEC3 (zone %s)", zone)
}

// parcourir suit les vraies délégations depuis la racine. Une absence de DS
// sur un nom qui n'est pas une délégation ne coupe pas la chaîne : le nom
// reste dans la zone courante. Renvoie la zone et les clés courantes, et
// insecure=true si une délégation sans DS a été rencontrée.
func (v *validateurDNSSEC) parcourir(nom string) (zone string, cles []*dns.DNSKEY, insecure bool, err error) {
	zone = "."
	cles, err = v.cleZone(zone, v.ancre)
	if err != nil {
		return "", nil, false, err
	}
	nom = canon(nom)
	if nom == "." {
		return zone, cles, false, nil
	}
	etiquettes := dns.SplitDomainName(nom)
	for i := len(etiquettes) - 1; i >= 0; i-- {
		candidat := strings.Join(etiquettes[i:], ".") + "."
		ds, err := v.dsDe(candidat, zone, cles)
		if errors.Is(err, ErrZoneNonSignee) {
			return zone, cles, true, nil
		}
		if err != nil {
			return "", nil, false, err
		}
		if ds == nil {
			continue
		}
		cles, err = v.cleZone(candidat, ds)
		if err != nil {
			return "", nil, false, err
		}
		zone = candidat
	}
	return zone, cles, false, nil
}

func (v *validateurDNSSEC) clesSignataire(signataire string) ([]*dns.DNSKEY, error) {
	signataire = canon(signataire)
	zone, cles, insecure, err := v.parcourir(signataire)
	if err != nil {
		return nil, err
	}
	if insecure {
		return nil, fmt.Errorf("signataire %s non ancré : délégation sans DS", signataire)
	}
	if zone != signataire {
		return nil, fmt.Errorf("signataire %s hors chaîne (zone %s)", signataire, zone)
	}
	return cles, nil
}

// dsDe interroge le DS d'un nom. Il renvoie nil sans erreur quand le nom
// n'est pas une délégation, et ErrZoneNonSignee quand la preuve signée montre
// une délégation sans DS (y compris NSEC3 opt-out).
func (v *validateurDNSSEC) dsDe(nom, zoneParent string, clesParent []*dns.DNSKEY) ([]*dns.DS, error) {
	rep, err := v.interroger(requete(nom, dns.TypeDS))
	if err != nil {
		return nil, fmt.Errorf("DS de %s : %w", nom, err)
	}
	var m dns.Msg
	if err := m.Unpack(rep); err != nil {
		return nil, fmt.Errorf("DS de %s illisible : %w", nom, err)
	}
	if m.Rcode != dns.RcodeSuccess && m.Rcode != dns.RcodeNameError {
		return nil, fmt.Errorf("DS de %s : RCODE %d", nom, m.Rcode)
	}
	var ds []*dns.DS
	var sig *dns.RRSIG
	for _, rr := range m.Answer {
		switch r := rr.(type) {
		case *dns.DS:
			ds = append(ds, r)
		case *dns.RRSIG:
			if r.TypeCovered == dns.TypeDS {
				sig = r
			}
		}
	}
	if len(ds) > 0 {
		if m.Rcode != dns.RcodeSuccess {
			return nil, fmt.Errorf("DS de %s : RCODE %d avec une réponse", nom, m.Rcode)
		}
		if sig == nil {
			return nil, fmt.Errorf("DS de %s non signé", nom)
		}
		if canon(sig.SignerName) != canon(zoneParent) {
			return nil, fmt.Errorf("DS de %s signé par %s, attendu %s", nom, sig.SignerName, zoneParent)
		}
		if err := v.verifierSignature(sig, rrset(m.Answer, ds[0].Hdr.Name, dns.TypeDS), clesParent); err != nil {
			return nil, fmt.Errorf("DS de %s : %w", nom, err)
		}
		return ds, nil
	}

	insecure, err := v.preuveAbsence(canon(zoneParent), clesParent, nom, dns.TypeDS, &m)
	if err != nil {
		// Un renvoi (NS sans SOA) signale une délégation non signée dont le
		// parent ne peut pas fournir de preuve DNSSEC.
		if referenceSansSOA(&m) {
			return nil, ErrZoneNonSignee
		}
		return nil, fmt.Errorf("absence de DS pour %s : %w", nom, err)
	}
	if insecure {
		return nil, ErrZoneNonSignee
	}
	return nil, nil
}

func (v *validateurDNSSEC) cleZone(zone string, ds []*dns.DS) ([]*dns.DNSKEY, error) {
	zone = canon(zone)
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
			for _, d := range ds {
				if correspondDS(r, d) {
					cles = append(cles, r)
					break
				}
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
		if canon(sig.SignerName) != zone || !sig.ValidityPeriod(time.Now()) {
			continue
		}
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
	// Relecture du 23/11 : miekg/dns ne vérifie ni la période de validité
	// (une vieille réponse signée se rejouerait indéfiniment) ni que le nom
	// signé est DANS la zone signataire (il compare des suffixes de chaîne :
	// example.test signerait badexample.test). Les deux sont faits ici.
	if !sig.ValidityPeriod(time.Now()) {
		return fmt.Errorf("signature %s/%d hors de sa période de validité", sig.Hdr.Name, sig.TypeCovered)
	}
	if len(rrset) == 0 || !dns.IsSubDomain(canon(sig.SignerName), canon(rrset[0].Header().Name)) {
		return fmt.Errorf("signature %s/%d : signataire %s hors de la zone du nom", sig.Hdr.Name, sig.TypeCovered, sig.SignerName)
	}
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

// preuveAbsence vérifie une preuve NSEC ou NSEC3 signée. Le booléen renvoyé
// indique une délégation sans DS (zone non signée).
func (v *validateurDNSSEC) preuveAbsence(zone string, cles []*dns.DNSKEY, qname string, qtype uint16, m *dns.Msg) (bool, error) {
	zone = canon(zone)
	qname = canon(qname)
	if !dns.IsSubDomain(zone, qname) {
		return false, fmt.Errorf("%s n'est pas sous la zone %s", qname, zone)
	}
	nsecs, nsec3s, err := v.preuvesSignees(zone, cles, m)
	if err != nil {
		return false, err
	}
	if len(nsec3s) > 0 {
		h, it, salt := nsec3s[0].Hash, nsec3s[0].Iterations, nsec3s[0].Salt
		for _, n := range nsec3s[1:] {
			if n.Hash != h || n.Iterations != it || n.Salt != salt {
				return false, errors.New("NSEC3 aux paramètres incohérents")
			}
		}
	}
	if len(nsecs) > 0 {
		insecure, ok, err := preuveNSEC(zone, qname, qtype, m.Rcode, nsecs)
		if err != nil {
			return false, err
		}
		if ok {
			return insecure, nil
		}
	}
	if len(nsec3s) > 0 {
		insecure, ok, err := preuveNSEC3(zone, qname, qtype, m.Rcode, nsec3s)
		if err != nil {
			return false, err
		}
		if ok {
			return insecure, nil
		}
	}
	return false, fmt.Errorf("preuve NSEC/NSEC3 absente pour %s/%d", qname, qtype)
}

// preuvesSignees renvoie les NSEC/NSEC3 dont la signature par la zone est
// valide. Les enregistrements non signés sont ignorés ; ils ne peuvent donc
// pas fabriquer une preuve.
func (v *validateurDNSSEC) preuvesSignees(zone string, cles []*dns.DNSKEY, m *dns.Msg) ([]*dns.NSEC, []*dns.NSEC3, error) {
	tous := append(append([]dns.RR{}, m.Answer...), m.Ns...)
	var nsecs []*dns.NSEC
	var nsec3s []*dns.NSEC3
	vus := make(map[string]bool)
	for _, sig := range signatures(tous) {
		if sig.TypeCovered != dns.TypeNSEC && sig.TypeCovered != dns.TypeNSEC3 {
			continue
		}
		if canon(sig.SignerName) != canon(zone) {
			continue
		}
		cle := canon(sig.Hdr.Name) + fmt.Sprintf("/%d", sig.TypeCovered)
		if vus[cle] {
			continue
		}
		rrs := rrset(tous, sig.Hdr.Name, sig.TypeCovered)
		if len(rrs) == 0 {
			continue
		}
		if err := v.verifierSignature(sig, rrs, cles); err != nil {
			continue
		}
		vus[cle] = true
		for _, rr := range rrs {
			switch r := rr.(type) {
			case *dns.NSEC:
				nsecs = append(nsecs, r)
			case *dns.NSEC3:
				nsec3s = append(nsec3s, r)
			}
		}
	}
	return nsecs, nsec3s, nil
}

func preuveNSEC(zone, qname string, qtype uint16, rcode int, nsecs []*dns.NSEC) (bool, bool, error) {
	if qtype == dns.TypeDS {
		if n := nsecCorrespond(nsecs, qname); n != nil {
			if bitmap(n.TypeBitMap, dns.TypeDS) {
				return false, false, errors.New("NSEC annonce un DS absent de la réponse")
			}
			return bitmap(n.TypeBitMap, dns.TypeNS) && !bitmap(n.TypeBitMap, dns.TypeSOA), true, nil
		}
		if nsecCouvre(nsecs, qname) != nil {
			return false, true, nil
		}
		return false, false, nil
	}
	if rcode == dns.RcodeNameError {
		couvrant := nsecCouvre(nsecs, qname)
		if couvrant == nil {
			return false, false, nil
		}
		ce := plusLongSuffixe(qname, couvrant.Hdr.Name)
		if !dns.IsSubDomain(zone, ce) || nsecCouvre(nsecs, etoile(ce)) == nil {
			return false, false, nil
		}
		return false, true, nil
	}
	if rcode != dns.RcodeSuccess {
		return false, false, nil
	}
	if n := nsecCorrespond(nsecs, qname); n != nil {
		if typeAbsent(n.TypeBitMap, qtype) {
			return false, true, nil
		}
		return false, false, errors.New("NSEC annonce le type demandé")
	}
	// Nom vide non terminal : un NSEC couvre le nom sans qu'il existe de RRset.
	if nsecCouvre(nsecs, qname) != nil {
		return false, true, nil
	}
	// NODATA synthétisé par un wildcard : le nom n'existe pas, le wildcard
	// existe mais ne porte pas le type.
	for _, ce := range ancetres(qname, zone) {
		suivant := prochainNom(ce, qname)
		if suivant == "" || nsecCouvre(nsecs, suivant) == nil {
			continue
		}
		if n := nsecCorrespond(nsecs, etoile(ce)); n != nil && typeAbsent(n.TypeBitMap, qtype) {
			return false, true, nil
		}
	}
	return false, false, nil
}

func preuveNSEC3(zone, qname string, qtype uint16, rcode int, nsec3s []*dns.NSEC3) (bool, bool, error) {
	if qtype == dns.TypeDS {
		if n := nsec3Correspond(nsec3s, qname); n != nil {
			if bitmap(n.TypeBitMap, dns.TypeDS) {
				return false, false, errors.New("NSEC3 annonce un DS absent de la réponse")
			}
			return bitmap(n.TypeBitMap, dns.TypeNS) && !bitmap(n.TypeBitMap, dns.TypeSOA), true, nil
		}
		if n := nsec3Couvre(nsec3s, qname); n != nil {
			// RFC 5155 8.6 : un NSEC3 opt-out couvrant le nom prouve une
			// délégation non signée.
			return n.Flags&1 != 0, true, nil
		}
		return false, false, nil
	}
	if rcode == dns.RcodeNameError {
		ce, suivant, ok := enclosPreuve(nsec3s, qname, zone)
		if !ok || nsec3Couvre(nsec3s, suivant) == nil {
			return false, false, nil
		}
		if nsec3Couvre(nsec3s, etoile(ce)) == nil {
			return false, false, nil
		}
		return false, true, nil
	}
	if rcode != dns.RcodeSuccess {
		return false, false, nil
	}
	if n := nsec3Correspond(nsec3s, qname); n != nil {
		if typeAbsent(n.TypeBitMap, qtype) {
			return false, true, nil
		}
		return false, false, errors.New("NSEC3 annonce le type demandé")
	}
	// Nom vide non terminal : preuve du plus proche enclos.
	ce, suivant, ok := enclosPreuve(nsec3s, qname, zone)
	if !ok || nsec3Couvre(nsec3s, suivant) == nil {
		return false, false, nil
	}
	etoilee := etoile(ce)
	if n := nsec3Correspond(nsec3s, etoilee); n != nil {
		if typeAbsent(n.TypeBitMap, qtype) {
			return false, true, nil
		}
		return false, false, errors.New("NSEC3 du wildcard annonce le type demandé")
	}
	if nsec3Couvre(nsec3s, etoilee) != nil {
		return false, true, nil
	}
	return false, false, nil
}

// enclosPreuve renvoie le plus proche enclos existant et le nom suivant à
// couvrir sur le chemin de qname.
func enclosPreuve(nsec3s []*dns.NSEC3, qname, zone string) (string, string, bool) {
	for _, ce := range ancetres(qname, zone) {
		if nsec3Correspond(nsec3s, ce) != nil {
			suivant := prochainNom(ce, qname)
			if suivant == "" {
				return "", "", false
			}
			return ce, suivant, true
		}
	}
	return "", "", false
}

func nsecCorrespond(nsecs []*dns.NSEC, nom string) *dns.NSEC {
	nom = canon(nom)
	for _, n := range nsecs {
		if canon(n.Hdr.Name) == nom {
			return n
		}
	}
	return nil
}

func nsecCouvre(nsecs []*dns.NSEC, nom string) *dns.NSEC {
	nom = canon(nom)
	for _, n := range nsecs {
		if nomCouvert(n.Hdr.Name, n.NextDomain, nom) {
			return n
		}
	}
	return nil
}

func nsec3Correspond(nsec3s []*dns.NSEC3, nom string) *dns.NSEC3 {
	for _, n := range nsec3s {
		if n.Match(nom) {
			return n
		}
	}
	return nil
}

func nsec3Couvre(nsec3s []*dns.NSEC3, nom string) *dns.NSEC3 {
	for _, n := range nsec3s {
		if n.Cover(nom) {
			return n
		}
	}
	return nil
}

// nomCouvert applique l'ordre canonique DNSSEC (RFC 4034 6.1) et le
// bouclage de fin de zone.
func nomCouvert(proprietaire, suivant, nom string) bool {
	proprietaire = canon(proprietaire)
	suivant = canon(suivant)
	nom = canon(nom)
	if proprietaire == suivant {
		return nom != proprietaire
	}
	if nomAvant(proprietaire, suivant) {
		return nomAvant(proprietaire, nom) && nomAvant(nom, suivant)
	}
	return nomAvant(proprietaire, nom) || nomAvant(nom, suivant)
}

func nomAvant(a, b string) bool {
	la := dns.SplitDomainName(a)
	lb := dns.SplitDomainName(b)
	for i := 1; ; i++ {
		if i > len(la) {
			return i <= len(lb)
		}
		if i > len(lb) {
			return false
		}
		x, y := la[len(la)-i], lb[len(lb)-i]
		if x != y {
			return x < y
		}
	}
}

func plusLongSuffixe(a, b string) string {
	n := dns.CompareDomainName(a, b)
	if n == 0 {
		return "."
	}
	etiquettes := dns.SplitDomainName(a)
	return strings.Join(etiquettes[len(etiquettes)-n:], ".") + "."
}

func etoile(zone string) string {
	if zone == "." {
		return "*."
	}
	return "*." + zone
}

// ancetres renvoie qname puis ses parents jusqu'à zone inclus.
func ancetres(qname, zone string) []string {
	etiquettes := dns.SplitDomainName(qname)
	z := dns.SplitDomainName(zone)
	if len(z) > len(etiquettes) {
		return nil
	}
	var out []string
	for i := 0; i <= len(etiquettes)-len(z); i++ {
		out = append(out, strings.Join(etiquettes[i:], ".")+".")
	}
	if zone == "." && (len(out) == 0 || out[len(out)-1] != ".") {
		out = append(out, ".")
	}
	return out
}

func prochainNom(enclos, qname string) string {
	e := dns.SplitDomainName(enclos)
	q := dns.SplitDomainName(qname)
	if len(q) <= len(e) {
		return ""
	}
	return strings.Join(q[len(q)-len(e)-1:], ".") + "."
}

func typeAbsent(types []uint16, qtype uint16) bool {
	return !bitmap(types, qtype) && !bitmap(types, dns.TypeCNAME)
}

func bitmap(types []uint16, typ uint16) bool {
	for _, t := range types {
		if t == typ {
			return true
		}
	}
	return false
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

func canon(nom string) string {
	return strings.ToLower(dns.Fqdn(nom))
}

func referenceSansSOA(m *dns.Msg) bool {
	var ns, soa bool
	for _, rr := range m.Ns {
		switch rr.(type) {
		case *dns.NS:
			ns = true
		case *dns.SOA:
			soa = true
		}
	}
	return ns && !soa
}

func requete(nom string, typ uint16) []byte {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(nom), typ)
	m.SetEdns0(1232, true) // DO : demander les signatures
	m.RecursionDesired = true
	brut, _ := m.Pack()
	return brut
}
