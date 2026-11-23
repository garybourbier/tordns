// TorDNS — lecture du protocole PROXY v2 de Tor (Mission 10).
//
// `HiddenServiceExportCircuitID haproxy` fait précéder chaque connexion d'un
// en-tête PROXY v2 dont l'identifiant unique est le circuit Tor. Le registre
// s'en sert pour limiter les inscriptions par circuit, pas par adresse réseau
// (derrière Tor, toutes les connexions viennent du même conteneur).
//
// Une connexion sans en-tête (healthcheck local) est acceptée telle quelle,
// sans circuit : la limite retombe alors sur l'adresse réseau.
package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net"
)

var signatureProxy = []byte{'\r', '\n', '\r', '\n', 0, '\r', '\n', 'Q', 'U', 'I', 'T', '\n'}

const typeUniqueID = 0x05

type connProxy struct {
	net.Conn
	lecteur *bufio.Reader
	source  net.Addr
	circuit string
}

func (c *connProxy) Read(p []byte) (int, error) { return c.lecteur.Read(p) }

func (c *connProxy) RemoteAddr() net.Addr {
	if c.source != nil {
		return c.source
	}
	return c.Conn.RemoteAddr()
}

// analyserProxy lit l'en-tête s'il est présent. Sans en-tête, il ne consomme
// rien et renvoie un circuit vide.
func analyserProxy(br *bufio.Reader) (net.Addr, string, error) {
	debut, err := br.Peek(len(signatureProxy))
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, bufio.ErrBufferFull) {
			return nil, "", nil
		}
		return nil, "", err
	}
	if string(debut) != string(signatureProxy) {
		return nil, "", nil
	}
	_, _ = br.Discard(len(signatureProxy))
	var entete [4]byte
	if _, err := io.ReadFull(br, entete[:]); err != nil {
		return nil, "", err
	}
	version := entete[0] >> 4
	commande := entete[0] & 0x0f
	if version != 2 || (commande != 0 && commande != 1) {
		return nil, "", errors.New("en-tête PROXY v2 invalide")
	}
	taille := int(binary.BigEndian.Uint16(entete[2:4]))
	if taille > 4096 {
		return nil, "", errors.New("en-tête PROXY v2 trop grand")
	}
	bloc := make([]byte, taille)
	if _, err := io.ReadFull(br, bloc); err != nil {
		return nil, "", err
	}
	if commande == 0 { // LOCAL : aucune adresse
		return nil, "", nil
	}
	famille := entete[1] >> 4
	var source net.Addr
	var apres int
	switch famille {
	case 1: // IPv4
		if len(bloc) < 12 {
			return nil, "", errors.New("adresse PROXY v2 tronquée")
		}
		source = &net.TCPAddr{
			IP:   net.IP(append([]byte(nil), bloc[0:4]...)),
			Port: int(binary.BigEndian.Uint16(bloc[8:10])),
		}
		apres = 12
	case 2: // IPv6
		if len(bloc) < 36 {
			return nil, "", errors.New("adresse PROXY v2 tronquée")
		}
		source = &net.TCPAddr{
			IP:   net.IP(append([]byte(nil), bloc[0:16]...)),
			Port: int(binary.BigEndian.Uint16(bloc[32:34])),
		}
		apres = 36
	default:
		return nil, "", nil
	}
	circuit := ""
	for apres+3 <= len(bloc) {
		typ := bloc[apres]
		long := int(binary.BigEndian.Uint16(bloc[apres+1 : apres+3]))
		apres += 3
		if apres+long > len(bloc) {
			break
		}
		if typ == typeUniqueID {
			circuit = string(bloc[apres : apres+long])
		}
		apres += long
	}
	return source, circuit, nil
}

type ecouteurProxy struct{ net.Listener }

func (e ecouteurProxy) Accept() (net.Conn, error) {
	c, err := e.Listener.Accept()
	if err != nil {
		return nil, err
	}
	br := bufio.NewReaderSize(c, 4096)
	source, circuit, err := analyserProxy(br)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	return &connProxy{Conn: c, lecteur: br, source: source, circuit: circuit}, nil
}
