package relais

import (
	"errors"
	"testing"
	"time"
)

// FuzzRelaisClient analyse les paquets UDP/TCP reçus par le relais local avant
// tout cache ou réseau. Les fonctions pures ne doivent jamais paniquer.
func FuzzRelaisClient(f *testing.F) {
	requete := []byte{
		0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01,
	}
	f.Add(requete)
	f.Add([]byte{0, 1, 2})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, msg []byte) {
		q, err := analyser(msg)
		if err != nil {
			return
		}
		_ = q.cle()
		_, _ = cacheable(msg, time.Hour)
		_ = ajuster(msg, q.id, 0)
		_ = servfail(msg)
		_ = verifierReponse(msg, msg)
	})
}

// FuzzValiderDNSSEC passe des réponses arbitraires au validateur. L'appel
// réseau est remplacé par une erreur : aucune sortie réseau pendant le fuzz.
func FuzzValiderDNSSEC(f *testing.F) {
	v, err := nouveauValidateur(func([]byte) ([]byte, error) {
		return nil, errors.New("hors ligne")
	}, ancreRacineDS)
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte{})
	f.Add([]byte{0x00, 0x01, 0x80, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	f.Fuzz(func(t *testing.T, reponse []byte) {
		_ = v.Valider(reponse)
	})
}
