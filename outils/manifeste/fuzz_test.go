package manifeste

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"
)

// FuzzManifeste vérifie qu'aucune entrée, même avec une signature ou une clé
// arbitraire, ne fait paniquer la vérification. Un second passage signe les
// octets avec une clé de test pour atteindre le parseur JSON.
func FuzzManifeste(f *testing.F) {
	f.Add([]byte(`{}`), make([]byte, ed25519.SignatureSize), []byte(ClePubliqueEpinglee))
	f.Add([]byte(`{"version":1,"expire":"2030-01-01T00:00:00Z","cibles":{}}`),
		make([]byte, ed25519.SignatureSize), []byte(ClePubliqueEpinglee))
	f.Add([]byte{}, []byte{}, []byte{})
	f.Add([]byte(`null`), make([]byte, ed25519.SignatureSize), []byte{})

	_, privee, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	publique := hex.EncodeToString(privee.Public().(ed25519.PublicKey))

	f.Fuzz(func(t *testing.T, brut, signature, cle []byte) {
		_, _ = Verifier(brut, signature, string(cle), time.Unix(1_800_000_000, 0))
		// Signature valide sur des octets arbitraires : exerce le JSON.
		sig := ed25519.Sign(privee, brut)
		_, _ = Verifier(brut, sig, publique, time.Unix(1_800_000_000, 0))
	})
}
