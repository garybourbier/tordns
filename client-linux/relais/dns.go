package relais

// Manipulation minimale du format DNS filaire (RFC 1035) : lecture de la
// question, calcul de la durée de cache et réécriture de l'identifiant et des
// TTL avant de rendre la réponse au client local.

import (
	"encoding/binary"
	"errors"
	"strings"
	"time"
)

const (
	typeOPT   = 41
	tailleMax = 65535
)

var errForme = errors.New("paquet DNS mal formé")

// question décrit la question d'une requête ; l'identifiant de transaction est
// volontairement exclu de la clé de cache.
type question struct {
	nom    string
	qtype  uint16
	qclass uint16
	do     bool
	id     uint16
}

// cle identifie une entrée de cache : même nom (insensible à la casse), même
// type, même classe et même exigence DNSSEC.
func (q question) cle() string {
	drapeau := "sans-dnssec"
	if q.do {
		drapeau = "dnssec"
	}
	return q.nom + "|" + itoaUint16(q.qtype) + "|" + itoaUint16(q.qclass) + "|" + drapeau
}

func itoaUint16(v uint16) string {
	var b [5]byte
	i := len(b)
	for {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
		if v == 0 {
			break
		}
	}
	return string(b[i:])
}

// lireNom décode un nom DNS à partir de l'offset donné et renvoie aussi
// l'offset qui suit le nom dans le flux d'origine (les pointeurs de
// compression sont suivis sans faire avancer cet offset).
func lireNom(msg []byte, debut int) (string, int, error) {
	if debut >= len(msg) {
		return "", 0, errForme
	}
	var sb strings.Builder
	off := debut
	fin := -1
	for sauts := 0; ; sauts++ {
		if sauts > 32 || off >= len(msg) {
			return "", 0, errForme
		}
		l := int(msg[off])
		switch {
		case l == 0:
			off++
			if fin < 0 {
				fin = off
			}
			if sb.Len() == 0 {
				sb.WriteByte('.')
			}
			return sb.String(), fin, nil
		case l&0xC0 == 0xC0:
			if off+2 > len(msg) {
				return "", 0, errForme
			}
			if fin < 0 {
				fin = off + 2
			}
			off = int(binary.BigEndian.Uint16(msg[off:off+2]) & 0x3FFF)
		case l&0xC0 != 0:
			return "", 0, errForme
		default:
			off++
			if off+l > len(msg) {
				return "", 0, errForme
			}
			sb.Write(msg[off : off+l])
			sb.WriteByte('.')
			off += l
		}
	}
}

// sauterRR avance après un enregistrement de ressource (nom + en-tête fixe +
// données), sans interpréter les données.
func sauterRR(msg []byte, off int) (int, error) {
	_, off, err := lireNom(msg, off)
	if err != nil {
		return 0, err
	}
	if off+10 > len(msg) {
		return 0, errForme
	}
	rdlen := int(binary.BigEndian.Uint16(msg[off+8 : off+10]))
	off += 10 + rdlen
	if off > len(msg) {
		return 0, errForme
	}
	return off, nil
}

// analyser lit la première question et le bit DO de l'OPT éventuel.
func analyser(msg []byte) (question, error) {
	if len(msg) < 12 {
		return question{}, errForme
	}
	if binary.BigEndian.Uint16(msg[4:6]) != 1 {
		return question{}, errForme
	}
	nom, off, err := lireNom(msg, 12)
	if err != nil {
		return question{}, err
	}
	if off+4 > len(msg) {
		return question{}, errForme
	}
	q := question{
		nom:    strings.ToLower(nom),
		qtype:  binary.BigEndian.Uint16(msg[off : off+2]),
		qclass: binary.BigEndian.Uint16(msg[off+2 : off+4]),
		id:     binary.BigEndian.Uint16(msg[0:2]),
	}
	off += 4

	an := int(binary.BigEndian.Uint16(msg[6:8]))
	ns := int(binary.BigEndian.Uint16(msg[8:10]))
	ar := int(binary.BigEndian.Uint16(msg[10:12]))
	for i := 0; i < an+ns; i++ {
		if off, err = sauterRR(msg, off); err != nil {
			return question{}, err
		}
	}
	for i := 0; i < ar; i++ {
		_, apresNom, err := lireNom(msg, off)
		if err != nil {
			return question{}, err
		}
		if apresNom+10 > len(msg) {
			return question{}, errForme
		}
		if binary.BigEndian.Uint16(msg[apresNom:apresNom+2]) == typeOPT {
			// Le champ TTL de l'OPT porte RCODE étendu, version, puis les
			// drapeaux 16 bits dont DO est le bit de poids fort (bit 15).
			if msg[apresNom+6]&0x80 != 0 {
				q.do = true
			}
		}
		if off, err = sauterRR(msg, off); err != nil {
			return question{}, err
		}
	}
	return q, nil
}

// cacheable indique si la réponse peut être mise en cache et pour combien de
// temps : réponses complètes (non tronquées), standard, NOERROR ou NXDOMAIN.
// Pour une réponse positive, seul le plus petit TTL de la section réponse
// compte. Pour NXDOMAIN ou NODATA, le TTL négatif suit le SOA (RFC 2308) :
// minimum du TTL du SOA et de son champ MINIMUM. Plancher d'une seconde,
// plafond ttlMax ; sans SOA, une réponse négative n'est pas gardée.
func cacheable(msg []byte, ttlMax time.Duration) (time.Duration, bool) {
	if len(msg) < 12 {
		return 0, false
	}
	flags := binary.BigEndian.Uint16(msg[2:4])
	if flags&0x8000 == 0 { // pas une réponse
		return 0, false
	}
	if flags&0x0200 != 0 { // tronquée
		return 0, false
	}
	if (flags>>11)&0xF != 0 { // opcode non standard
		return 0, false
	}
	rcode := flags & 0xF
	if rcode != 0 && rcode != 3 {
		return 0, false
	}

	off := 12
	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	for i := 0; i < qd; i++ {
		var err error
		if _, off, err = lireNom(msg, off); err != nil || off+4 > len(msg) {
			return 0, false
		}
		off += 4
	}

	an := int(binary.BigEndian.Uint16(msg[6:8]))
	ns := int(binary.BigEndian.Uint16(msg[8:10]))
	plusPetit := uint32(0)
	trouve := false

	// Réponse positive : la section réponse fait foi, pas l'autorité.
	for i := 0; i < an; i++ {
		var typ uint16
		var ttl uint32
		var err error
		off, typ, ttl, err = lireRR(msg, off)
		if err != nil {
			return 0, false
		}
		if typ != typeOPT && (!trouve || ttl < plusPetit) {
			plusPetit = ttl
			trouve = true
		}
	}
	if rcode == 0 && an > 0 {
		if !trouve {
			return 0, false
		}
		d := bornerTTL(plusPetit, ttlMax)
		return d, d > 0
	}

	// NXDOMAIN ou NODATA : TTL négatif porté par le SOA de l'autorité.
	negatif := uint32(0)
	if ns > 0 {
		for i := 0; i < ns; i++ {
			debutDonnees := 0
			var typ uint16
			var ttl uint32
			var err error
			off, typ, ttl, debutDonnees, err = lireRRDonnees(msg, off)
			if err != nil {
				return 0, false
			}
			if typ != 6 || debutDonnees+4 > len(msg) {
				continue
			}
			// Les quatre derniers octets des données du SOA sont MINIMUM.
			minimum := binary.BigEndian.Uint32(msg[off-4 : off])
			valeur := ttl
			if minimum < valeur {
				valeur = minimum
			}
			if !trouve || valeur < negatif {
				negatif = valeur
				trouve = true
			}
		}
	}
	if !trouve {
		return 0, false
	}
	d := bornerTTL(negatif, ttlMax)
	return d, d > 0
}

func bornerTTL(secondes uint32, ttlMax time.Duration) time.Duration {
	if secondes == 0 {
		return 0
	}
	d := time.Duration(secondes) * time.Second
	if d < time.Second {
		d = time.Second
	}
	if d > ttlMax {
		d = ttlMax
	}
	return d
}

// lireRR avance après un enregistrement et renvoie son type et son TTL.
func lireRR(msg []byte, off int) (int, uint16, uint32, error) {
	fin, typ, ttl, _, err := lireRRDonnees(msg, off)
	return fin, typ, ttl, err
}

// lireRRDonnees renvoie aussi le début des données de l'enregistrement.
func lireRRDonnees(msg []byte, off int) (int, uint16, uint32, int, error) {
	_, apresNom, err := lireNom(msg, off)
	if err != nil || apresNom+10 > len(msg) {
		return 0, 0, 0, 0, errForme
	}
	typ := binary.BigEndian.Uint16(msg[apresNom : apresNom+2])
	ttl := binary.BigEndian.Uint32(msg[apresNom+4 : apresNom+8])
	rdlen := int(binary.BigEndian.Uint16(msg[apresNom+8 : apresNom+10]))
	debut := apresNom + 10
	fin := debut + rdlen
	if fin > len(msg) {
		return 0, 0, 0, 0, errForme
	}
	return fin, typ, ttl, debut, nil
}

// ajuster renvoie une copie de la réponse avec l'identifiant du client et des
// TTL diminués du temps passé en cache (jamais en dessous de 1 s).
func ajuster(msg []byte, id uint16, ecoule time.Duration) []byte {
	out := append([]byte(nil), msg...)
	if len(out) < 12 {
		return out
	}
	binary.BigEndian.PutUint16(out[0:2], id)
	secondes := uint32(ecoule / time.Second)

	off := 12
	qd := int(binary.BigEndian.Uint16(out[4:6]))
	for i := 0; i < qd; i++ {
		var err error
		if _, off, err = lireNom(out, off); err != nil || off+4 > len(out) {
			return out
		}
		off += 4
	}
	sections := []int{
		int(binary.BigEndian.Uint16(out[6:8])),
		int(binary.BigEndian.Uint16(out[8:10])),
		int(binary.BigEndian.Uint16(out[10:12])),
	}
	for _, n := range sections {
		for i := 0; i < n; i++ {
			_, apresNom, err := lireNom(out, off)
			if err != nil || apresNom+10 > len(out) {
				return out
			}
			typ := binary.BigEndian.Uint16(out[apresNom : apresNom+2])
			ttl := binary.BigEndian.Uint32(out[apresNom+4 : apresNom+8])
			if typ != typeOPT && ttl > 0 {
				if ttl <= secondes {
					ttl = 1
				} else {
					ttl -= secondes
				}
				binary.BigEndian.PutUint32(out[apresNom+4:apresNom+8], ttl)
			}
			rdlen := int(binary.BigEndian.Uint16(out[apresNom+8 : apresNom+10]))
			off = apresNom + 10 + rdlen
			if off > len(out) {
				return out
			}
		}
	}
	return out
}

// servfail construit une réponse SERVFAIL reprenant la question du client.
func servfail(msg []byte) []byte {
	if len(msg) < 12 {
		return nil
	}
	out := append([]byte(nil), msg[:12]...)
	flags := binary.BigEndian.Uint16(out[2:4])
	// QR + RA, on conserve RD et CD, rcode = 2 (SERVFAIL).
	flags = 0x8000 | 0x0080 | (flags & 0x0110) | 2
	binary.BigEndian.PutUint16(out[2:4], flags)
	binary.BigEndian.PutUint16(out[4:6], 1)
	binary.BigEndian.PutUint16(out[6:8], 0)
	binary.BigEndian.PutUint16(out[8:10], 0)
	binary.BigEndian.PutUint16(out[10:12], 0)
	// Reprise de la question encodée telle quelle.
	_, fin, err := lireNom(msg, 12)
	if err != nil || fin+4 > len(msg) {
		return nil
	}
	out = append(out, msg[12:fin+4]...)
	return out
}
