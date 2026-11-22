package manifeste

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func signer(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func valide(version int64) Manifeste {
	return Manifeste{
		Version: version,
		Expire:  "2027-01-01T00:00:00Z",
		Cibles: map[string]Cible{
			"client-linux-amd64": {
				URL:    "https://exemple.invalid/maj/tordns-client",
				Taille: 1234,
				SHA256: strings.Repeat("ab", 32),
			},
		},
		Images: map[string]string{
			"unbound": "ghcr.io/tordns/unbound@sha256:" + strings.Repeat("cd", 32),
		},
		Adresses: map[string]string{
			"coeur": strings.Repeat("a", 56) + ".onion",
		},
	}
}

func sigler(t *testing.T, m Manifeste, priv ed25519.PrivateKey) ([]byte, []byte) {
	t.Helper()
	brut, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return brut, ed25519.Sign(priv, brut)
}

func TestManifesteValide(t *testing.T) {
	pub, priv := signer(t)
	brut, sig := sigler(t, valide(2), priv)
	m, err := Accepter(brut, sig, hex.EncodeToString(pub), 1, time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("manifeste valide refusé : %v", err)
	}
	if m.Version != 2 || m.Images["unbound"] == "" {
		t.Fatalf("manifeste mal décodé : %+v", m)
	}
}

func TestRefusSignatureAlteree(t *testing.T) {
	pub, priv := signer(t)
	brut, sig := sigler(t, valide(2), priv)
	brut[10] ^= 0x01 // un octet du JSON change, la signature non
	if _, err := Verifier(brut, sig, hex.EncodeToString(pub), time.Now()); err == nil {
		t.Fatal("manifeste altéré accepté")
	}
}

func TestRefusMauvaiseCle(t *testing.T) {
	_, priv := signer(t)
	brut, sig := sigler(t, valide(2), priv)
	autre, _ := signer(t)
	if _, err := Verifier(brut, sig, hex.EncodeToString(autre), time.Now()); err == nil {
		t.Fatal("signature vérifiée avec la mauvaise clé")
	}
}

func TestRefusRejeuVersion(t *testing.T) {
	pub, priv := signer(t)
	brut, sig := sigler(t, valide(1), priv)
	for _, installee := range []int64{1, 2} {
		if _, err := Accepter(brut, sig, hex.EncodeToString(pub), installee, time.Now()); err == nil {
			t.Fatalf("version 1 acceptée au-dessus de %d", installee)
		}
	}
}

func TestRefusExpire(t *testing.T) {
	pub, priv := signer(t)
	m := valide(2)
	m.Expire = "2026-01-01T00:00:00Z"
	brut, sig := sigler(t, m, priv)
	if _, err := Verifier(brut, sig, hex.EncodeToString(pub), time.Now()); err == nil {
		t.Fatal("manifeste expiré accepté")
	}
}

func TestRefusImageParEtiquette(t *testing.T) {
	pub, priv := signer(t)
	m := valide(2)
	m.Images["unbound"] = "ghcr.io/tordns/unbound:latest"
	brut, sig := sigler(t, m, priv)
	if _, err := Verifier(brut, sig, hex.EncodeToString(pub), time.Now()); err == nil {
		t.Fatal("image par étiquette acceptée")
	}
}

func TestRefusSHAInvalide(t *testing.T) {
	pub, priv := signer(t)
	m := valide(2)
	c := m.Cibles["client-linux-amd64"]
	c.SHA256 = "pas-un-sha"
	m.Cibles["client-linux-amd64"] = c
	brut, sig := sigler(t, m, priv)
	if _, err := Verifier(brut, sig, hex.EncodeToString(pub), time.Now()); err == nil {
		t.Fatal("SHA-256 invalide accepté")
	}
}

func TestCleSuivante(t *testing.T) {
	pub, priv := signer(t)
	m := valide(2)
	m.CleSuivante = strings.Repeat("ef", 32)
	brut, sig := sigler(t, m, priv)
	lu, err := Verifier(brut, sig, hex.EncodeToString(pub), time.Now())
	if err != nil || lu.CleSuivante != m.CleSuivante {
		t.Fatalf("rotation non lue : %v", err)
	}
}
