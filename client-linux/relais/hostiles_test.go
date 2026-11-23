package relais

import (
	"math/rand"
	"testing"
	"time"
)

func TestPaquetsDnsHostiles(t *testing.T) {
	hasard := rand.New(rand.NewSource(13))
	for i := 0; i < 10_000; i++ {
		msg := make([]byte, hasard.Intn(600))
		hasard.Read(msg)
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("boucle %d, %d octets : panique %v", i, len(msg), r)
				}
			}()
			_, _ = analyser(msg)
			_, _ = cacheable(msg, 3600*1e9)
			_ = ajuster(msg, 1, 12*time.Second)
			_ = servfail(msg)
		}()
	}
}
