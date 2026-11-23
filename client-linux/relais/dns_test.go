package relais

import (
	"encoding/binary"
	"reflect"
	"testing"
	"time"
)

func encoderNom(nom string) []byte {
	var out []byte
	debut := 0
	for i := 0; i <= len(nom); i++ {
		if i == len(nom) || nom[i] == '.' {
			if i > debut {
				out = append(out, byte(i-debut))
				out = append(out, nom[debut:i]...)
			}
			debut = i + 1
		}
	}
	return append(out, 0)
}

func requeteTest(id uint16, nom string, qtype uint16, do bool) []byte {
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[0:2], id)
	binary.BigEndian.PutUint16(msg[2:4], 0x0100) // RD
	binary.BigEndian.PutUint16(msg[4:6], 1)
	msg = append(msg, encoderNom(nom)...)
	msg = binary.BigEndian.AppendUint16(msg, qtype)
	msg = binary.BigEndian.AppendUint16(msg, 1)
	if do {
		// OPT : racine, type 41, classe 1232, TTL avec DO, pas de données.
		msg = append(msg, 0, 0, 41, 0x04, 0xD0, 0x00, 0x00, 0x80, 0x00, 0, 0)
		binary.BigEndian.PutUint16(msg[10:12], 1)
	}
	return msg
}

func reponseTest(id uint16, ttl uint32, drapeaux uint16) []byte {
	msg := requeteTest(id, "example.com", 1, false)
	binary.BigEndian.PutUint16(msg[2:4], drapeaux)
	binary.BigEndian.PutUint16(msg[6:8], 1) // un enregistrement en réponse
	msg = append(msg, 0xC0, 12)             // pointeur vers la question
	msg = append(msg, 0, 1, 0, 1)           // type A, classe IN
	msg = binary.BigEndian.AppendUint32(msg, ttl)
	msg = append(msg, 0, 4, 192, 0, 2, 1) // longueur 4, adresse
	return msg
}

func TestAnalyserQuestionEtDO(t *testing.T) {
	q, err := analyser(requeteTest(0x1234, "ExAmPle.COM", 28, true))
	if err != nil {
		t.Fatal(err)
	}
	if q.nom != "example.com." || q.qtype != 28 || q.qclass != 1 || !q.do || q.id != 0x1234 {
		t.Fatalf("question inattendue : %+v", q)
	}
	q2, err := analyser(requeteTest(1, "example.com", 1, false))
	if err != nil || q2.do {
		t.Fatalf("DO ne devrait pas être levé : %+v (%v)", q2, err)
	}
	if q.cle() == q2.cle() {
		t.Fatal("les clés avec et sans DNSSEC doivent différer")
	}
}

func TestLireNomCompresse(t *testing.T) {
	msg := append(requeteTest(1, "example.com", 1, false), 0xC0, 12)
	nom, suivant, err := lireNom(msg, len(msg)-2)
	if err != nil {
		t.Fatal(err)
	}
	if nom != "example.com." || suivant != len(msg) {
		t.Fatalf("nom=%q suivant=%d", nom, suivant)
	}
}

func TestCacheable(t *testing.T) {
	complet := reponseTest(1, 300, 0x8180)
	ttl, ok := cacheable(complet, time.Hour)
	if !ok || ttl != 300*time.Second {
		t.Fatalf("ttl=%v ok=%v", ttl, ok)
	}

	tronquee := reponseTest(1, 300, 0x8380) // TC
	if _, ok := cacheable(tronquee, time.Hour); ok {
		t.Fatal("une réponse tronquée ne doit pas être cachée")
	}
	servfail := reponseTest(1, 300, 0x8182)
	if _, ok := cacheable(servfail, time.Hour); ok {
		t.Fatal("un SERVFAIL ne doit pas être caché")
	}
	requete := requeteTest(1, "example.com", 1, false)
	if _, ok := cacheable(requete, time.Hour); ok {
		t.Fatal("une requête (QR=0) ne doit pas être cachée")
	}
}

func TestCacheableIgnoreLOPT(t *testing.T) {
	msg := reponseTest(1, 300, 0x8180)
	// OPT supplémentaire avec un TTL élevé (drapeaux étendus).
	msg = append(msg, 0, 0, 41, 0x04, 0xD0, 0x00, 0x00, 0x80, 0x00, 0, 0)
	binary.BigEndian.PutUint16(msg[10:12], 1)
	ttl, ok := cacheable(msg, time.Hour)
	if !ok || ttl != 300*time.Second {
		t.Fatalf("le TTL de l'OPT ne doit pas compter : ttl=%v ok=%v", ttl, ok)
	}
}

func TestAjusterIdentifiantEtTTL(t *testing.T) {
	msg := reponseTest(0x1111, 300, 0x8180)
	copie := append([]byte(nil), msg...)
	ajuste := ajuster(msg, 0xBEEF, 12*time.Second)
	if binary.BigEndian.Uint16(ajuste[0:2]) != 0xBEEF {
		t.Fatal("identifiant non réécrit")
	}
	_, finQuestion, _ := lireNom(ajuste, 12)
	_, apresNom, _ := lireNom(ajuste, finQuestion+4)
	ttl := binary.BigEndian.Uint32(ajuste[apresNom+4 : apresNom+8])
	if ttl != 288 {
		t.Fatalf("TTL ajusté = %d, attendu 288", ttl)
	}
	if !reflect.DeepEqual(msg, copie) {
		t.Fatal("la réponse en cache a été modifiée")
	}

	// Une ancienneté supérieure au TTL laisse 1 s, jamais 0.
	ajuste = ajuster(msg, 1, 10*time.Minute)
	_, finQuestion, _ = lireNom(ajuste, 12)
	_, apresNom, _ = lireNom(ajuste, finQuestion+4)
	if ttl := binary.BigEndian.Uint32(ajuste[apresNom+4 : apresNom+8]); ttl != 1 {
		t.Fatalf("TTL plancher = %d, attendu 1", ttl)
	}
}

func TestServfailReprendLaQuestion(t *testing.T) {
	req := requeteTest(0x2222, "example.com", 1, false)
	rep := servfail(req)
	if len(rep) != len(req) {
		t.Fatalf("taille %d, attendu %d", len(rep), len(req))
	}
	if binary.BigEndian.Uint16(rep[2:4])&0xF != 2 {
		t.Fatalf("rcode = %d, attendu SERVFAIL", binary.BigEndian.Uint16(rep[2:4])&0xF)
	}
	if binary.BigEndian.Uint16(rep[0:2]) != 0x2222 || binary.BigEndian.Uint16(rep[4:6]) != 1 {
		t.Fatal("identifiant ou question perdus")
	}
}

func ajouterRR(msg []byte, typ uint16, ttl uint32, donnees []byte) []byte {
	msg = append(msg, 0xC0, 12) // pointeur vers le nom de la question
	msg = binary.BigEndian.AppendUint16(msg, typ)
	msg = append(msg, 0, 1) // classe IN
	msg = binary.BigEndian.AppendUint32(msg, ttl)
	msg = binary.BigEndian.AppendUint16(msg, uint16(len(donnees)))
	return append(msg, donnees...)
}

func donneesSOA(minimum uint32) []byte {
	out := []byte{0, 0, 0, 0} // mname et rname : pointeurs vers la racine
	for i := 0; i < 4; i++ {  // serial, refresh, retry, expire
		out = binary.BigEndian.AppendUint32(out, 3600)
	}
	return binary.BigEndian.AppendUint32(out, minimum)
}

func reponseNegative(id uint16, rcode uint16, avecSOA bool) []byte {
	msg := requeteTest(id, "absent.example", 1, false)
	binary.BigEndian.PutUint16(msg[2:4], 0x8180|rcode)
	if avecSOA {
		binary.BigEndian.PutUint16(msg[8:10], 1) // une autorité
		msg = ajouterRR(msg, 6, 600, donneesSOA(60))
	}
	return msg
}

func TestCacheableReponsePositiveIgnoreAutorite(t *testing.T) {
	msg := reponseTest(1, 300, 0x8180)
	binary.BigEndian.PutUint16(msg[8:10], 1)
	msg = ajouterRR(msg, 6, 30, donneesSOA(10))
	ttl, ok := cacheable(msg, time.Hour)
	if !ok || ttl != 300*time.Second {
		t.Fatalf("le TTL de l'autorité ne doit pas compter : ttl=%v ok=%v", ttl, ok)
	}
}

func TestCacheableNegatifSuitLeSOA(t *testing.T) {
	ttl, ok := cacheable(reponseNegative(1, 3, true), time.Hour)
	if !ok || ttl != 60*time.Second {
		t.Fatalf("NXDOMAIN : ttl=%v ok=%v, attendu 60 s (minimum du SOA)", ttl, ok)
	}
	// NODATA : NOERROR sans réponse, même règle.
	ttl, ok = cacheable(reponseNegative(1, 0, true), time.Hour)
	if !ok || ttl != 60*time.Second {
		t.Fatalf("NODATA : ttl=%v ok=%v, attendu 60 s", ttl, ok)
	}
	if _, ok := cacheable(reponseNegative(1, 3, false), time.Hour); ok {
		t.Fatal("un NXDOMAIN sans SOA ne doit pas être caché")
	}
}

func TestCacheableBornes(t *testing.T) {
	msg := reponseNegative(1, 3, true)
	// TTL 0 : jamais de mise en cache, même avec un SOA.
	soa := len(msg) - len(donneesSOA(60)) - 10
	binary.BigEndian.PutUint32(msg[soa+4:soa+8], 0)
	binary.BigEndian.PutUint32(msg[len(msg)-4:], 0)
	if ttl, ok := cacheable(msg, time.Hour); ok {
		t.Fatalf("TTL nul : ttl=%v ok=%v, attendu non caché", ttl, ok)
	}
	// Plafond de 1 h.
	long := reponseNegative(1, 3, true)
	soa = len(long) - len(donneesSOA(60)) - 10
	binary.BigEndian.PutUint32(long[soa+4:soa+8], 7200)
	binary.BigEndian.PutUint32(long[len(long)-4:], 7200)
	if ttl, ok := cacheable(long, time.Hour); !ok || ttl != time.Hour {
		t.Fatalf("plafond : ttl=%v ok=%v, attendu 1 h", ttl, ok)
	}
}
