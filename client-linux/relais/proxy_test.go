package relais

import (
	"net"
	"testing"
	"time"
)

func TestProxyJoignable(t *testing.T) {
	ecoute, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	adresse := ecoute.Addr().String()
	if err := ProxyJoignable(adresse, time.Second); err != nil {
		t.Fatalf("SOCKS local refusé : %v", err)
	}
	ecoute.Close()
	if err := ProxyJoignable(adresse, 200*time.Millisecond); err == nil {
		t.Fatal("SOCKS fermé accepté")
	}
}
