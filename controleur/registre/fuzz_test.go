package main

import (
	"bufio"
	"bytes"
	"testing"
)

// FuzzEnTeteProxy fait lire des en-têtes PROXY v2 arbitraires au registre.
// La lecture est bornée (4096 octets) et ne doit jamais paniquer.
func FuzzEnTeteProxy(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("GET /etat HTTP/1.1\r\n\r\n"))
	f.Add(signatureProxy)
	ipv4 := append(append([]byte(nil), signatureProxy...),
		0x21, 0x11, 0x00, 0x0c,
		192, 0, 2, 1, 198, 51, 100, 1, 0x1f, 0x90, 0x23, 0x28)
	f.Add(ipv4)
	ipv6 := append(append([]byte(nil), signatureProxy...),
		0x21, 0x21, 0x00, 0x24,
		0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
		0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
		0x1f, 0x90, 0x23, 0x28)
	f.Add(ipv6)

	f.Fuzz(func(t *testing.T, brut []byte) {
		br := bufio.NewReader(bytes.NewReader(brut))
		_, _, _ = analyserProxy(br)
	})
}
