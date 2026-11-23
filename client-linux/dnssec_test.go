package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
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
	sig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: rrset[0].Header().Name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
		TypeCovered: rrset[0].Header().Rrtype,
		Algorithm:   dns.ED25519,
		Labels:      uint8(dns.CountLabel(rrset[0].Header().Name)),
		OrigTtl:     rrset[0].Header().Ttl,
		Expiration:  uint32(time.Now().Add(24 * time.Hour).Unix()),
		Inception:   uint32(time.Now().Add(-time.Hour).Unix()),
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

// fauxResolveur sert une chaîne racine → test. → example.test. entièrement
// signée, et permet d'altérer la réponse A.
type fauxResolveur struct {
	racine, tld, exemple zoneTest
	altererA             bool
	sansDS               bool
}

func (f *fauxResolveur) interroger(brut []byte) ([]byte, error) {
	var q dns.Msg
	if err := q.Unpack(brut); err != nil {
		return nil, err
	}
	question := q.Question[0]
	rep := new(dns.Msg)
	rep.SetReply(&q)
	rep.RecursionAvailable = true
	switch strings.ToLower(question.Name) {
	case ".":
		rrset := []dns.RR{f.racine.cle}
		rep.Answer = append(rrset, signer(f.racine, rrset))
	case "test.":
		if question.Qtype == dns.TypeDS {
			ds := dsDe(f.tld)
			rrset := []dns.RR{ds}
			rep.Answer = append(rrset, signer(f.racine, rrset))
		} else {
			rrset := []dns.RR{f.tld.cle}
			rep.Answer = append(rrset, signer(f.tld, rrset))
		}
	case "example.test.":
		switch question.Qtype {
		case dns.TypeDS:
			if f.sansDS {
				return rep.Pack()
			}
			ds := dsDe(f.exemple)
			rrset := []dns.RR{ds}
			rep.Answer = append(rrset, signer(f.tld, rrset))
		case dns.TypeDNSKEY:
			rrset := []dns.RR{f.exemple.cle}
			rep.Answer = append(rrset, signer(f.exemple, rrset))
		default:
			a := &dns.A{
				Hdr: dns.RR_Header{Name: "example.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   []byte{192, 0, 2, 1},
			}
			rrset := []dns.RR{a}
			rep.Answer = append(rrset, signer(f.exemple, rrset))
			if f.altererA {
				a.A = []byte{203, 0, 113, 9}
			}
		}
	default:
		rep.Rcode = dns.RcodeNameError
	}
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

func TestDNSSECReponseAlteree(t *testing.T) {
	f, ancre := chaineDeTest(t)
	f.altererA = true
	v, err := nouveauValidateur(f.interroger, ancre)
	if err != nil {
		t.Fatal(err)
	}
	rep, _ := f.interroger(requeteA("example.test"))
	if err := v.Valider(rep); err == nil {
		t.Fatal("réponse dont l'adresse A a été modifiée acceptée")
	}
}

func TestDNSSECZoneSansDS(t *testing.T) {
	f, ancre := chaineDeTest(t)
	f.sansDS = true
	v, err := nouveauValidateur(f.interroger, ancre)
	if err != nil {
		t.Fatal(err)
	}
	rep, _ := f.interroger(requeteA("example.test"))
	if err := v.Valider(rep); !errors.Is(err, ErrZoneNonSignee) {
		t.Fatalf("zone sans DS : %v, ErrZoneNonSignee attendu", err)
	}
}

func TestDNSSECAncreInvalide(t *testing.T) {
	if _, err := nouveauValidateur(func([]byte) ([]byte, error) { return nil, nil }, "pas une ancre"); err == nil {
		t.Fatal("ancre invalide acceptée")
	}
}
