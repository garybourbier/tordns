package relais

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type zoneTest struct {
	nom  string
	cle  *dns.DNSKEY
	priv ed25519.PrivateKey
}

func nouvelleZone(t *testing.T, nom string, graine byte) zoneTest {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(bytesRemplis(graine))
	pub := priv.Public().(ed25519.PublicKey)
	cle := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: dns.Fqdn(nom), Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.ED25519,
		PublicKey: base64.StdEncoding.EncodeToString(pub),
	}
	return zoneTest{nom: dns.Fqdn(nom), cle: cle, priv: priv}
}

func bytesRemplis(v byte) []byte {
	b := make([]byte, ed25519.SeedSize)
	for i := range b {
		b[i] = v
	}
	return b
}

func signer(zone zoneTest, rrset []dns.RR) *dns.RRSIG {
	return signerEntre(zone, rrset, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
}

func signerEntre(zone zoneTest, rrset []dns.RR, debut, fin time.Time) *dns.RRSIG {
	sig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: rrset[0].Header().Name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
		TypeCovered: rrset[0].Header().Rrtype,
		Algorithm:   dns.ED25519,
		Labels:      uint8(dns.CountLabel(rrset[0].Header().Name)),
		OrigTtl:     rrset[0].Header().Ttl,
		Expiration:  uint32(fin.Unix()),
		Inception:   uint32(debut.Unix()),
		KeyTag:      zone.cle.KeyTag(),
		SignerName:  zone.nom,
	}
	if err := sig.Sign(zone.priv, rrset); err != nil {
		panic(err)
	}
	return sig
}

func dsDe(zone zoneTest) *dns.DS {
	ds := zone.cle.ToDS(dns.SHA256)
	ds.Hdr.Name = zone.nom
	ds.Hdr.Ttl = 3600
	return ds
}

func nsec(proprietaire, suivant string, types ...uint16) *dns.NSEC {
	return &dns.NSEC{
		Hdr:        dns.RR_Header{Name: dns.Fqdn(proprietaire), Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: 300},
		NextDomain: dns.Fqdn(suivant),
		TypeBitMap: typesTries(types...),
	}
}

func typesTries(types ...uint16) []uint16 {
	out := append([]uint16(nil), types...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// fauxResolveur sert une chaîne racine → test. → example.test. entièrement
// signée. Selon le mode, il fabrique une preuve NSEC ou NSEC3.
type fauxResolveur struct {
	racine, tld, exemple zoneTest
	altererA             bool
	injecterA            bool
	sansDS               bool
	// renvoiForge : le nœud répond à la question DS de example.test. par un
	// renvoi NS sans SOA ni NSEC ni signature, puis sert une adresse non signée
	// (relecture du 24/11, point 2 : il désactivait ainsi DNSSEC pour la zone).
	renvoiForge bool
	mode        string
	// signatureA, si non nil, remplace la signature de l'enregistrement A
	// (attaques : signature périmée, signataire voisin).
	signatureA func(rrset []dns.RR) *dns.RRSIG
}

func (f *fauxResolveur) interroger(brut []byte) ([]byte, error) {
	var q dns.Msg
	if err := q.Unpack(brut); err != nil {
		return nil, err
	}
	if len(q.Question) != 1 {
		return nil, errors.New("question absente")
	}
	question := q.Question[0]
	rep := new(dns.Msg)
	rep.SetReply(&q)
	rep.RecursionAvailable = true
	nom := strings.ToLower(question.Name)

	switch nom {
	case ".":
		if question.Qtype == dns.TypeDS {
			rep.Rcode = dns.RcodeNameError
			return rep.Pack()
		}
		rrset := []dns.RR{f.racine.cle}
		rep.Answer = append(rrset, signer(f.racine, rrset))
		return rep.Pack()
	case "test.":
		if question.Qtype == dns.TypeDS || question.Qtype == dns.TypeDNSKEY {
			return f.reponseZone(rep, question, f.racine, f.tld)
		}
	case "example.test.":
		if question.Qtype == dns.TypeDS && f.renvoiForge {
			rep.Ns = append(rep.Ns, &dns.NS{
				Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60},
				Ns:  "ns.attaquant.invalid.",
			})
			return rep.Pack()
		}
		if question.Qtype == dns.TypeDS && f.sansDS {
			n := nsec("example.test.", "zzz.test.", dns.TypeNS, dns.TypeNSEC, dns.TypeRRSIG)
			rep.Ns = append(rep.Ns, n, signer(f.tld, []dns.RR{n}))
			return rep.Pack()
		}
		if question.Qtype == dns.TypeDS || question.Qtype == dns.TypeDNSKEY {
			return f.reponseZone(rep, question, f.tld, f.exemple)
		}
	case "unsigned.example.test.":
		if question.Qtype == dns.TypeDS && strings.Contains(f.mode, "optout") {
			for _, n := range nsec3Serie(f, f.exemple, 1) {
				rep.Ns = append(rep.Ns, n, signer(f.exemple, []dns.RR{n}))
			}
			return rep.Pack()
		}
	}

	if question.Qtype == dns.TypeA {
		switch f.mode {
		case "nsec":
			if nom == "absent.example.test." {
				return f.nxdomainNSEC(rep)
			}
			if nom == "present.example.test." {
				return f.nodataNSEC(rep, nom, dns.TypeTXT)
			}
		case "nsec-sans-wildcard":
			if nom == "absent.example.test." {
				return f.nxdomainNSECSansWildcard(rep)
			}
		case "nsec-type":
			if nom == "present.example.test." {
				return f.nodataNSEC(rep, nom, dns.TypeA)
			}
		case "nsec3":
			if nom == "absent3.example.test." {
				return f.nxdomainNSEC3(rep)
			}
			if nom == "present3.example.test." {
				return f.nodataNSEC3(rep, nom, false)
			}
		case "nsec3-type":
			if nom == "present3.example.test." {
				return f.nodataNSEC3(rep, nom, true)
			}
		}
	}

	a := &dns.A{
		Hdr: dns.RR_Header{Name: nom, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   []byte{192, 0, 2, 1},
	}
	rrset := []dns.RR{a}
	if f.signatureA != nil {
		rep.Answer = append(rrset, f.signatureA(rrset))
	} else if !f.sansDS && !f.renvoiForge && !strings.HasSuffix(nom, ".unsigned.example.test.") {
		rep.Answer = append(rrset, signer(f.exemple, rrset))
	} else {
		rep.Answer = append(rep.Answer, a)
	}
	if f.altererA {
		a.A = []byte{203, 0, 113, 9}
	}
	if f.injecterA {
		rep.Answer = append(rep.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: nom, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   []byte{203, 0, 113, 10},
		})
	}
	return rep.Pack()
}

func (f *fauxResolveur) reponseZone(rep *dns.Msg, question dns.Question, parent, zone zoneTest) ([]byte, error) {
	if question.Qtype == dns.TypeDS {
		ds := dsDe(zone)
		rrset := []dns.RR{ds}
		rep.Answer = append(rrset, signer(parent, rrset))
		return rep.Pack()
	}
	rrset := []dns.RR{zone.cle}
	rep.Answer = append(rrset, signer(zone, rrset))
	return rep.Pack()
}

func (f *fauxResolveur) nxdomainNSEC(rep *dns.Msg) ([]byte, error) {
	rep.Rcode = dns.RcodeNameError
	ns := []*dns.NSEC{
		nsec("example.test.", "a.example.test.", dns.TypeSOA, dns.TypeNS, dns.TypeDNSKEY, dns.TypeNSEC, dns.TypeRRSIG),
		nsec("a.example.test.", "zzz.example.test.", dns.TypeA, dns.TypeNSEC, dns.TypeRRSIG),
	}
	for _, n := range ns {
		rep.Ns = append(rep.Ns, n, signer(f.exemple, []dns.RR{n}))
	}
	return rep.Pack()
}

func (f *fauxResolveur) nxdomainNSECSansWildcard(rep *dns.Msg) ([]byte, error) {
	rep.Rcode = dns.RcodeNameError
	n := nsec("a.example.test.", "zzz.example.test.", dns.TypeA, dns.TypeNSEC, dns.TypeRRSIG)
	rep.Ns = append(rep.Ns, n, signer(f.exemple, []dns.RR{n}))
	return rep.Pack()
}

func (f *fauxResolveur) nodataNSEC(rep *dns.Msg, nom string, types ...uint16) ([]byte, error) {
	types = append(types, dns.TypeNSEC, dns.TypeRRSIG)
	n := nsec(nom, "zzz.example.test.", types...)
	rep.Ns = append(rep.Ns, n, signer(f.exemple, []dns.RR{n}))
	return rep.Pack()
}

func nsec3(zone zoneTest, proprietaire, suivant string, flags uint8, types ...uint16) *dns.NSEC3 {
	return &dns.NSEC3{
		Hdr:        dns.RR_Header{Name: dns.Fqdn(proprietaire), Rrtype: dns.TypeNSEC3, Class: dns.ClassINET, Ttl: 300},
		Hash:       dns.SHA1,
		Flags:      flags,
		Iterations: 0,
		SaltLength: 2,
		Salt:       "AABB",
		HashLength: 20,
		NextDomain: suivant,
		TypeBitMap: typesTries(types...),
	}
}

// nsec3Serie fabrique une chaîne NSEC3 cyclique sur quelques noms de la zone.
// Toute autre empreinte tombe donc dans un intervalle couvert.
func nsec3Serie(f *fauxResolveur, zone zoneTest, flags uint8) []*dns.NSEC3 {
	types := map[string][]uint16{
		"example.test.":          {dns.TypeSOA, dns.TypeNS, dns.TypeDNSKEY, dns.TypeNSEC3, dns.TypeRRSIG},
		"a.example.test.":        {dns.TypeA, dns.TypeNSEC3, dns.TypeRRSIG},
		"zzz.example.test.":      {dns.TypeA, dns.TypeNSEC3, dns.TypeRRSIG},
		"present3.example.test.": {dns.TypeTXT, dns.TypeNSEC3, dns.TypeRRSIG},
	}
	noms := make([]string, 0, len(types))
	for n := range types {
		noms = append(noms, n)
	}
	sort.Slice(noms, func(i, j int) bool {
		return dns.HashName(noms[i], dns.SHA1, 0, "AABB") < dns.HashName(noms[j], dns.SHA1, 0, "AABB")
	})
	var out []*dns.NSEC3
	for i, n := range noms {
		suivant := dns.HashName(noms[(i+1)%len(noms)], dns.SHA1, 0, "AABB")
		h := dns.HashName(n, dns.SHA1, 0, "AABB")
		out = append(out, nsec3(zone, h+"."+zone.nom, suivant, flags, types[n]...))
	}
	return out
}

func (f *fauxResolveur) nxdomainNSEC3(rep *dns.Msg) ([]byte, error) {
	rep.Rcode = dns.RcodeNameError
	for _, n := range nsec3Serie(f, f.exemple, 0) {
		rep.Ns = append(rep.Ns, n, signer(f.exemple, []dns.RR{n}))
	}
	return rep.Pack()
}

func (f *fauxResolveur) nodataNSEC3(rep *dns.Msg, nom string, annoncerA bool) ([]byte, error) {
	h := dns.HashName(nom, dns.SHA1, 0, "AABB")
	types := []uint16{dns.TypeTXT, dns.TypeNSEC3, dns.TypeRRSIG}
	if annoncerA {
		types = append(types, dns.TypeA)
	}
	n := nsec3(f.exemple, h+"."+f.exemple.nom, h, 0, types...)
	rep.Ns = append(rep.Ns, n, signer(f.exemple, []dns.RR{n}))
	return rep.Pack()
}

func chaineDeTest(t *testing.T) (*fauxResolveur, string) {
	t.Helper()
	f := &fauxResolveur{
		racine:  nouvelleZone(t, ".", 1),
		tld:     nouvelleZone(t, "test.", 2),
		exemple: nouvelleZone(t, "example.test.", 3),
	}
	ancre := dsDe(f.racine)
	texte := fmt.Sprintf("%d %d %d %s", ancre.KeyTag, ancre.Algorithm, ancre.DigestType, ancre.Digest)
	return f, texte
}

func requeteA(nom string) []byte {
	return requete(nom, dns.TypeA)
}

func validerReponse(t *testing.T, f *fauxResolveur, nom string) error {
	t.Helper()
	ancre := dsDe(f.racine)
	texte := fmt.Sprintf("%d %d %d %s", ancre.KeyTag, ancre.Algorithm, ancre.DigestType, ancre.Digest)
	v, err := nouveauValidateur(f.interroger, texte)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := f.interroger(requeteA(nom))
	if err != nil {
		t.Fatal(err)
	}
	return v.Valider(rep)
}

func TestDNSSECChaineValide(t *testing.T) {
	f, ancre := chaineDeTest(t)
	v, err := nouveauValidateur(f.interroger, ancre)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := f.interroger(requeteA("example.test"))
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Valider(rep); err != nil {
		t.Fatalf("chaîne valide refusée : %v", err)
	}
}

func TestDNSSECChaineHote(t *testing.T) {
	f, _ := chaineDeTest(t)
	if err := validerReponse(t, f, "www.example.test"); err != nil {
		t.Fatalf("nom d'hôte dans une zone signée refusé : %v", err)
	}
}

func TestDNSSECReponseAlteree(t *testing.T) {
	f, _ := chaineDeTest(t)
	f.altererA = true
	if err := validerReponse(t, f, "example.test"); err == nil {
		t.Fatal("réponse dont l'adresse A a été modifiée acceptée")
	}
}

func TestDNSSECReponseAvecRRsetNonSigne(t *testing.T) {
	f, _ := chaineDeTest(t)
	f.injecterA = true
	if err := validerReponse(t, f, "www.example.test"); err == nil {
		t.Fatal("RRset A non signé ajouté à une réponse signée accepté")
	}
}

func TestDNSSECZoneSansDS(t *testing.T) {
	f, _ := chaineDeTest(t)
	f.sansDS = true
	if err := validerReponse(t, f, "example.test"); !errors.Is(err, ErrZoneNonSignee) {
		t.Fatalf("zone sans DS : %v, ErrZoneNonSignee attendu", err)
	}
}

func TestDNSSECAncreInvalide(t *testing.T) {
	if _, err := nouveauValidateur(func([]byte) ([]byte, error) { return nil, nil }, "pas une ancre"); err == nil {
		t.Fatal("ancre invalide acceptée")
	}
}

func TestDNSSECNSECNXDOMAIN(t *testing.T) {
	f, _ := chaineDeTest(t)
	f.mode = "nsec"
	if err := validerReponse(t, f, "absent.example.test"); err != nil {
		t.Fatalf("NXDOMAIN NSEC refusé : %v", err)
	}
}

func TestDNSSECNSECNXDOMAINSansWildcard(t *testing.T) {
	f, _ := chaineDeTest(t)
	f.mode = "nsec-sans-wildcard"
	if err := validerReponse(t, f, "absent.example.test"); err == nil {
		t.Fatal("NXDOMAIN sans preuve d'absence du wildcard accepté")
	}
}

func TestDNSSECNSECNODATA(t *testing.T) {
	f, _ := chaineDeTest(t)
	f.mode = "nsec"
	if err := validerReponse(t, f, "present.example.test"); err != nil {
		t.Fatalf("NODATA NSEC refusé : %v", err)
	}
}

func TestDNSSECNSECNODATAAnnonceType(t *testing.T) {
	f, _ := chaineDeTest(t)
	f.mode = "nsec-type"
	if err := validerReponse(t, f, "present.example.test"); err == nil {
		t.Fatal("NODATA NSEC qui annonce le type A accepté")
	}
}

func TestDNSSECNSEC3NXDOMAIN(t *testing.T) {
	f, _ := chaineDeTest(t)
	f.mode = "nsec3"
	if err := validerReponse(t, f, "absent3.example.test"); err != nil {
		t.Fatalf("NXDOMAIN NSEC3 refusé : %v", err)
	}
}

func TestDNSSECNSEC3NODATA(t *testing.T) {
	f, _ := chaineDeTest(t)
	f.mode = "nsec3"
	if err := validerReponse(t, f, "present3.example.test"); err != nil {
		t.Fatalf("NODATA NSEC3 refusé : %v", err)
	}
}

func TestDNSSECNSEC3NODATAAnnonceType(t *testing.T) {
	f, _ := chaineDeTest(t)
	f.mode = "nsec3-type"
	if err := validerReponse(t, f, "present3.example.test"); err == nil {
		t.Fatal("NODATA NSEC3 qui annonce le type A accepté")
	}
}

func TestDNSSECNSEC3OptOutZoneSansDS(t *testing.T) {
	f, _ := chaineDeTest(t)
	f.mode = "nsec3-optout"
	if err := validerReponse(t, f, "www.unsigned.example.test"); !errors.Is(err, ErrZoneNonSignee) {
		t.Fatalf("délégation opt-out sans DS : %v, ErrZoneNonSignee attendu", err)
	}
}

// Relecture Claude du 23/11 : un nœud qui rejoue une réponse signée dont la
// signature a expiré (ou n'est pas encore valide) ne doit pas passer.
func TestDNSSECSignaturePerimeeRefusee(t *testing.T) {
	f, _ := chaineDeTest(t)
	f.signatureA = func(rrset []dns.RR) *dns.RRSIG {
		return signerEntre(f.exemple, rrset, time.Now().Add(-60*24*time.Hour), time.Now().Add(-30*24*time.Hour))
	}
	if err := validerReponse(t, f, "www.example.test"); err == nil {
		t.Fatal("signature expirée depuis 30 jours acceptée")
	}
	f.signatureA = func(rrset []dns.RR) *dns.RRSIG {
		return signerEntre(f.exemple, rrset, time.Now().Add(24*time.Hour), time.Now().Add(48*time.Hour))
	}
	if err := validerReponse(t, f, "www.example.test"); err == nil {
		t.Fatal("signature pas encore valide acceptée")
	}
}

// Relecture Claude du 23/11 : miekg/dns ne compare le signataire au nom que
// par suffixe de chaîne. La zone example.test ne doit pas pouvoir signer
// badexample.test (une zone voisine, pas une sous-zone).
func TestDNSSECSignataireVoisinRefuse(t *testing.T) {
	f, _ := chaineDeTest(t)
	f.signatureA = func(rrset []dns.RR) *dns.RRSIG { return signer(f.exemple, rrset) }
	if err := validerReponse(t, f, "badexample.test"); err == nil {
		t.Fatal("badexample.test signé par la zone example.test accepté")
	}
	if err := validerReponse(t, f, "www.example.test"); err != nil {
		t.Fatalf("sous-domaine légitime refusé : %v", err)
	}
}

// Relecture du 24/11, point 2 : un renvoi forgé (NS sans SOA, aucune preuve
// NSEC/NSEC3, aucune signature) ne doit JAMAIS faire passer une zone signée pour
// non signée. Le mode auto accepterait sinon l'adresse sans validation.
func TestDNSSECRenvoiForgeSansPreuveRefuse(t *testing.T) {
	f, _ := chaineDeTest(t)
	f.renvoiForge = true
	err := validerReponse(t, f, "example.test")
	if err == nil || errors.Is(err, ErrZoneNonSignee) {
		t.Fatalf("renvoi forgé accepté comme zone non signée : %v", err)
	}
}

// Relecture du 24/11, point 1 : pendant un roulement de la KSK racine, plusieurs
// ancres coexistent ; la chaîne est valide si AU MOINS UNE la valide.
func TestDNSSECPlusieursAncresUneSuffit(t *testing.T) {
	f, vraie := chaineDeTest(t)
	autre := nouvelleZone(t, ".", 9)
	fausse := dsDe(autre)
	texte := fmt.Sprintf("%d %d %d %s; %s", fausse.KeyTag, fausse.Algorithm, fausse.DigestType, fausse.Digest, vraie)
	v, err := nouveauValidateur(f.interroger, texte)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := f.interroger(requeteA("example.test"))
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Valider(rep); err != nil {
		t.Fatalf("chaîne valide refusée avec deux ancres : %v", err)
	}
	// Et avec la seule ancre qui ne signe pas, refus.
	seule := fmt.Sprintf("%d %d %d %s", fausse.KeyTag, fausse.Algorithm, fausse.DigestType, fausse.Digest)
	v, err = nouveauValidateur(f.interroger, seule)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Valider(rep); err == nil {
		t.Fatal("chaîne acceptée par une ancre qui ne la signe pas")
	}
}

// Les ancres livrées sont celles de l'IANA, KSK-2024 comprise.
func TestDNSSECAncresLivrees(t *testing.T) {
	if !strings.Contains(ancreRacineDS, "38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16") {
		t.Fatal("KSK-2024 (38696) absente des ancres livrées")
	}
	v, err := nouveauValidateur(func([]byte) ([]byte, error) { return nil, nil }, ancreRacineDS)
	if err != nil || len(v.ancre) != 2 {
		t.Fatalf("ancres livrées : %v, %d", err, len(v.ancre))
	}
}
