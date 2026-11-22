package main

import (
	"testing"
	"time"
)

func TestCacheLRUEvinceLaPlusAncienne(t *testing.T) {
	c := nouveauCache(2)
	c.poser("a", []byte{1}, time.Minute)
	c.poser("b", []byte{2}, time.Minute)
	if _, _, ok := c.obtenir("a"); !ok {
		t.Fatal("a devrait être présent")
	}
	c.poser("c", []byte{3}, time.Minute)
	if _, _, ok := c.obtenir("b"); ok {
		t.Fatal("b aurait dû être évincé (LRU)")
	}
	if _, _, ok := c.obtenir("a"); !ok {
		t.Fatal("a devait être conservé après rafraîchissement")
	}
	if c.taille() != 2 {
		t.Fatalf("taille = %d, attendu 2", c.taille())
	}
}

func TestCacheExpiration(t *testing.T) {
	c := nouveauCache(4)
	maintenant := time.Unix(1000, 0)
	c.maintenant = func() time.Time { return maintenant }
	c.poser("cle", []byte{1, 2}, 2*time.Second)

	if _, age, ok := c.obtenir("cle"); !ok || age != 0 {
		t.Fatalf("entrée fraîche : ok=%v age=%v", ok, age)
	}
	maintenant = maintenant.Add(1500 * time.Millisecond)
	if _, age, ok := c.obtenir("cle"); !ok || age != 1500*time.Millisecond {
		t.Fatalf("âge attendu 1,5 s, obtenu %v (ok=%v)", age, ok)
	}
	maintenant = maintenant.Add(time.Second)
	if _, _, ok := c.obtenir("cle"); ok {
		t.Fatal("entrée expirée encore servie")
	}
	if c.taille() != 0 {
		t.Fatalf("taille après expiration = %d, attendu 0", c.taille())
	}
}

func TestCacheTtlNulIgnore(t *testing.T) {
	c := nouveauCache(4)
	c.poser("cle", []byte{1}, 0)
	if _, _, ok := c.obtenir("cle"); ok {
		t.Fatal("une entrée de TTL nul ne doit pas être mise en cache")
	}
}
