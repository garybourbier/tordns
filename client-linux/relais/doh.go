package relais

// Client DoH (RFC 8484) transporté dans un flux SOCKS5 vers le service caché
// Tor v3. Aucune connexion DNS directe n'est effectuée : tout passe par le
// démon Tor local.

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

type connexion struct {
	net.Conn
	lecteur *bufio.Reader
}

type clientDoH struct {
	onion string
	socks string
	delai time.Duration
	dispo chan *connexion
}

func nouveauClientDoH(onion, socks string, delai time.Duration, taillePool int) *clientDoH {
	if taillePool < 1 {
		taillePool = 1
	}
	return &clientDoH{
		onion: onion,
		socks: socks,
		delai: delai,
		dispo: make(chan *connexion, taillePool),
	}
}

func (c *clientDoH) emprunter() (*connexion, error) {
	select {
	case cn := <-c.dispo:
		return cn, nil
	default:
		return c.ouvrir()
	}
}

func (c *clientDoH) rendre(cn *connexion) {
	if err := cn.SetDeadline(time.Time{}); err != nil {
		cn.Close()
		return
	}
	select {
	case c.dispo <- cn:
	default:
		cn.Close()
	}
}

// ouvrir établit une connexion TCP vers le proxy SOCKS puis lui demande de
// joindre onion:80. L'adresse est transmise par nom (ATYP 3) pour que Tor
// résolve le service caché lui-même.
func (c *clientDoH) ouvrir() (*connexion, error) {
	if c.onion == "" {
		return nil, errors.New("adresse .onion absente")
	}
	if len(c.onion) > 255 {
		return nil, errors.New("adresse .onion trop longue")
	}
	dialer := net.Dialer{Timeout: c.delai}
	conn, err := dialer.Dial("tcp", c.socks)
	if err != nil {
		return nil, fmt.Errorf("proxy SOCKS %s : %w", c.socks, err)
	}
	succes := false
	defer func() {
		if !succes {
			conn.Close()
		}
	}()
	if err := conn.SetDeadline(time.Now().Add(c.delai)); err != nil {
		return nil, err
	}

	// Poignée de main : version 5, une seule méthode, « sans authentification ».
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return nil, err
	}
	var reponse [2]byte
	if _, err := io.ReadFull(conn, reponse[:]); err != nil {
		return nil, fmt.Errorf("poignée SOCKS5 : %w", err)
	}
	if reponse[0] != 0x05 || reponse[1] != 0x00 {
		return nil, fmt.Errorf("SOCKS5 refuse la méthode sans authentification (%v)", reponse)
	}

	requete := make([]byte, 0, 7+len(c.onion))
	requete = append(requete, 0x05, 0x01, 0x00, 0x03, byte(len(c.onion)))
	requete = append(requete, c.onion...)
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], 80)
	requete = append(requete, port[:]...)
	if _, err := conn.Write(requete); err != nil {
		return nil, err
	}

	// Réponse CONNECT : version, code, réservé, type d'adresse, adresse, port.
	var entete [4]byte
	if _, err := io.ReadFull(conn, entete[:]); err != nil {
		return nil, fmt.Errorf("réponse SOCKS5 : %w", err)
	}
	if entete[0] != 0x05 {
		return nil, fmt.Errorf("version SOCKS5 inattendue : %d", entete[0])
	}
	if entete[1] != 0x00 {
		return nil, fmt.Errorf("SOCKS5 refuse la connexion : code %d", entete[1])
	}
	var longueur int
	switch entete[3] {
	case 0x01:
		longueur = 4
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			return nil, err
		}
		longueur = int(l[0])
	case 0x04:
		longueur = 16
	default:
		return nil, fmt.Errorf("type d'adresse SOCKS5 inconnu : %d", entete[3])
	}
	if _, err := io.CopyN(io.Discard, conn, int64(longueur+2)); err != nil {
		return nil, err
	}
	succes = true
	return &connexion{Conn: conn, lecteur: bufio.NewReader(conn)}, nil
}

// poster envoie une requête DoH en POST et renvoie le corps de la réponse.
// La connexion reste réutilisable si le serveur ne demande pas sa fermeture.
func (c *clientDoH) poster(cn *connexion, msg []byte) ([]byte, error) {
	if err := cn.SetDeadline(time.Now().Add(c.delai)); err != nil {
		return nil, err
	}
	var entete strings.Builder
	fmt.Fprintf(&entete, "POST /dns-query HTTP/1.1\r\nHost: %s\r\n", c.onion)
	entete.WriteString("Content-Type: application/dns-message\r\n")
	entete.WriteString("Accept: application/dns-message\r\n")
	fmt.Fprintf(&entete, "Content-Length: %d\r\n", len(msg))
	entete.WriteString("Connection: keep-alive\r\n\r\n")
	if _, err := cn.Write(append([]byte(entete.String()), msg...)); err != nil {
		return nil, err
	}

	ligne, err := cn.lecteur.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("lecture du statut HTTP : %w", err)
	}
	champs := strings.Fields(ligne)
	if len(champs) < 2 || !strings.HasPrefix(champs[0], "HTTP/") {
		return nil, fmt.Errorf("statut HTTP illisible : %q", strings.TrimSpace(ligne))
	}
	code, err := strconv.Atoi(champs[1])
	if err != nil {
		return nil, fmt.Errorf("code HTTP illisible : %q", champs[1])
	}

	longueur := -1
	fermer := false
	for {
		ligne, err = cn.lecteur.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("lecture des en-têtes HTTP : %w", err)
		}
		if ligne == "\r\n" || ligne == "\n" {
			break
		}
		nom, valeur, ok := strings.Cut(ligne, ":")
		if !ok {
			return nil, fmt.Errorf("en-tête HTTP illisible : %q", strings.TrimSpace(ligne))
		}
		switch strings.ToLower(strings.TrimSpace(nom)) {
		case "content-length":
			longueur, err = strconv.Atoi(strings.TrimSpace(valeur))
			if err != nil || longueur < 0 {
				return nil, errors.New("Content-Length invalide")
			}
		case "connection":
			fermer = strings.EqualFold(strings.TrimSpace(valeur), "close")
		}
	}
	if code != 200 {
		return nil, fmt.Errorf("DoH : HTTP %d", code)
	}
	if longueur < 0 || longueur > tailleMax {
		return nil, errors.New("réponse DoH sans Content-Length exploitable")
	}
	corps := make([]byte, longueur)
	if _, err := io.ReadFull(cn.lecteur, corps); err != nil {
		return nil, fmt.Errorf("corps DoH incomplet : %w", err)
	}
	if fermer {
		cn.Close()
	}
	return corps, nil
}

// verifierReponse contrôle que la réponse appartient bien à la requête envoyée.
func verifierReponse(requete, reponse []byte) error {
	if len(reponse) < 12 {
		return errors.New("réponse DNS trop courte")
	}
	if binary.BigEndian.Uint16(reponse[0:2]) != binary.BigEndian.Uint16(requete[0:2]) {
		return errors.New("identifiant de transaction différent")
	}
	if binary.BigEndian.Uint16(reponse[2:4])&0x8000 == 0 {
		return errors.New("paquet reçu sans le drapeau de réponse")
	}
	return nil
}
