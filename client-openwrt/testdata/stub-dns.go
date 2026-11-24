//go:build ignore

// Stub DNS utilisé UNIQUEMENT par scripts/verifier-m23.sh.
//
// Il écoute sur 127.0.0.1:5353 dans l'image OpenWrt de test et répond à toute
// question A par 93.184.216.34. Cette adresse est publique et hors des plages
// réservées (TEST-NET, RFC 5737) que la protection anti-rebind de dnsmasq
// rejette en journalisant le nom. Il sert à prouver que dnsmasq transfère
// réellement vers 127.0.0.1#5353 : la valeur vient du stub, pas du réseau.
// Aucun nom de domaine n'est journalisé.
package main

import (
	"flag"
	"fmt"
	"net"
)

func main() {
	ecoute := flag.String("ecoute", "127.0.0.1:5353", "adresse d'écoute UDP")
	flag.Parse()
	adresse, err := net.ResolveUDPAddr("udp", *ecoute)
	if err != nil {
		panic(err)
	}
	conn, err := net.ListenUDP("udp", adresse)
	if err != nil {
		panic(err)
	}
	fmt.Printf("stub-dns à l'écoute sur %s\n", *ecoute)
	tampon := make([]byte, 1500)
	for {
		n, source, err := conn.ReadFromUDP(tampon)
		if err != nil || n < 12 {
			continue
		}
		question := tampon[12:n]
		fin := len(question)
		for i := 0; i+4 < len(question); i++ {
			if question[i] == 0 {
				fin = i + 5
				break
			}
		}
		if fin > len(question) {
			continue
		}
		reponse := make([]byte, 0, 12+fin+16)
		reponse = append(reponse, tampon[0], tampon[1]) // identifiant
		reponse = append(reponse, 0x84, 0x00)           // réponse, RD+RA
		reponse = append(reponse, 0, 1, 0, 1, 0, 0, 0, 0)
		reponse = append(reponse, question[:fin]...)
		reponse = append(reponse, 0xc0, 0x0c) // pointeur vers la question
		reponse = append(reponse, 0, 1, 0, 1) // A, IN
		reponse = append(reponse, 0, 0, 0, 60)
		reponse = append(reponse, 0, 4, 93, 184, 216, 34)
		_, _ = conn.WriteToUDP(reponse, source)
	}
}
