package main

import (
	"encoding/base64"
	"testing"
)

// FuzzPasserelleDoH couvre les deux entrées d'une requête DoH : le corps POST
// application/dns-message et le paramètre `dns=` d'un GET. Le résolveur réseau
// n'est pas appelé : on fuzz les décodeurs et le parseur de réponse amont.
func FuzzPasserelleDoH(f *testing.F) {
	requete := []byte{
		0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01,
	}
	reponse := append([]byte(nil), requete...)
	reponse[2] = 0x81
	reponse[3] = 0x80
	reponse[7] = 0x01
	reponse = append(reponse, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 0x7f, 0x00, 0x00, 0x01)
	f.Add(requete, "POST")
	f.Add(requete, "GET")
	f.Add(reponse, "POST")
	f.Add([]byte{}, "GET")

	f.Fuzz(func(t *testing.T, corps []byte, methode string) {
		// GET : le paramètre dns= est du base64url sans padding (ou avec).
		encode := base64.RawURLEncoding.EncodeToString(corps)
		if decode, err := decoderBase64URL(encode); err == nil {
			if len(decode) < 12 || len(decode) > tailleMaxRequete {
				return
			}
		}
		// POST : les deux bornes de taille précèdent le parseur.
		if len(corps) < 12 || len(corps) > tailleMaxRequete {
			return
		}
		_, _ = lireReponse(corps)
		_ = estTronquee(corps)
	})
}
