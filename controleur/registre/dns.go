// TorDNS — requêtes DoH minimales pour les sondes du registre (Mission 10).
//
// Le registre n'a pas besoin d'un résolveur complet : il construit une requête
// A avec EDNS0/DO, l'envoie en DoH (GET ?dns=base64url) et ne lit que l'en-tête
// DNS : code de retour et bit AD. Aucun nom de domaine n'est journalisé.
package main

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

var errReponseDNS = errors.New("réponse DNS invalide")

type resultatDNS struct {
	Rcode uint16
	AD    bool
	IPs   []string // enregistrements A, triés
}

func requeteA(nom string) ([]byte, error) {
	nom = strings.TrimSuffix(nom, ".")
	if nom == "" || len(nom) > 253 {
		return nil, errReponseDNS
	}
	// En-tête : identifiant 0, RD, une question, aucune réponse, un OPT.
	m := make([]byte, 12, 512)
	binary.BigEndian.PutUint16(m[0:2], 0)
	binary.BigEndian.PutUint16(m[2:4], 0x0100) // RD
	binary.BigEndian.PutUint16(m[4:6], 1)
	binary.BigEndian.PutUint16(m[10:12], 1) // ARCOUNT : OPT
	for _, etiquette := range strings.Split(nom, ".") {
		if etiquette == "" || len(etiquette) > 63 {
			return nil, errReponseDNS
		}
		m = append(m, byte(len(etiquette)))
		m = append(m, etiquette...)
	}
	m = append(m, 0)             // fin du nom
	m = append(m, 0, 1)          // QTYPE A
	m = append(m, 0, 1)          // QCLASS IN
	m = append(m, 0)             // OPT : nom racine
	m = append(m, 0, 41)         // TYPE OPT
	m = append(m, 0x10, 0x00)    // UDP payload 4096
	m = append(m, 0, 0, 0x80, 0) // TTL, bit DO
	m = append(m, 0, 0)          // RDLEN
	return m, nil
}

// lireNom avance dans un nom DNS, éventuellement compressé. La valeur du nom
// n'est pas nécessaire : seule la position de fin compte.
func lireNom(msg []byte, debut int) (int, error) {
	off := debut
	for sauts := 0; sauts < 32; sauts++ {
		if off >= len(msg) {
			return 0, errReponseDNS
		}
		long := int(msg[off])
		switch {
		case long == 0:
			return off + 1, nil
		case long&0xc0 == 0xc0:
			if off+1 >= len(msg) {
				return 0, errReponseDNS
			}
			return off + 2, nil
		case long > 63:
			return 0, errReponseDNS
		}
		off += 1 + long
	}
	return 0, errReponseDNS
}

// lireEntete lit l'en-tête, le RCODE, le bit AD et les enregistrements A de la
// réponse. Une intersection d'adresses suffit : un CDN peut renvoyer un autre
// ensemble. Une réponse signée dont les adresses sont disjointes de la
// référence reste un mensonge, car elle prétend valider une autre donnée.
func lireEntete(reponse []byte) (resultatDNS, error) {
	if len(reponse) < 12 {
		return resultatDNS{}, errReponseDNS
	}
	if binary.BigEndian.Uint16(reponse[0:2]) != 0 {
		return resultatDNS{}, errReponseDNS
	}
	drapeaux := binary.BigEndian.Uint16(reponse[2:4])
	if drapeaux&0x8000 == 0 {
		return resultatDNS{}, errReponseDNS
	}
	questions := int(binary.BigEndian.Uint16(reponse[4:6]))
	if questions != 1 {
		return resultatDNS{}, errReponseDNS
	}
	resultat := resultatDNS{
		Rcode: drapeaux & 0x000f,
		AD:    drapeaux&0x0020 != 0,
	}
	off, err := lireNom(reponse, 12)
	if err != nil {
		return resultatDNS{}, err
	}
	off += 4 // QTYPE + QCLASS
	for i := 0; i < int(binary.BigEndian.Uint16(reponse[6:8])); i++ {
		off, err = lireNom(reponse, off)
		if err != nil || off+10 > len(reponse) {
			return resultatDNS{}, errReponseDNS
		}
		typ := binary.BigEndian.Uint16(reponse[off : off+2])
		long := int(binary.BigEndian.Uint16(reponse[off+8 : off+10]))
		off += 10
		if off+long > len(reponse) {
			return resultatDNS{}, errReponseDNS
		}
		if typ == 1 && long == 4 {
			resultat.IPs = append(resultat.IPs, net.IP(reponse[off:off+4]).String())
		}
		off += long
	}
	sort.Strings(resultat.IPs)
	return resultat, nil
}

// interrogerDoH envoie la requête à une URL DoH complète et renvoie l'en-tête.
// L'URL ne doit jamais apparaître dans un journal : seul le résultat compte.
func interrogerDoH(client *http.Client, urlDoH, nom string) (resultatDNS, int, error) {
	requete, err := requeteA(nom)
	if err != nil {
		return resultatDNS{}, 0, err
	}
	adresse := urlDoH
	if strings.Contains(adresse, "?") {
		adresse += "&dns="
	} else {
		adresse += "?dns="
	}
	adresse += base64.RawURLEncoding.EncodeToString(requete)
	reponse, err := client.Get(adresse)
	if err != nil {
		return resultatDNS{}, 0, err
	}
	defer reponse.Body.Close()
	if reponse.StatusCode != http.StatusOK {
		return resultatDNS{}, reponse.StatusCode, fmt.Errorf("DoH : HTTP %d", reponse.StatusCode)
	}
	corps, err := io.ReadAll(io.LimitReader(reponse.Body, 8192))
	if err != nil {
		return resultatDNS{}, reponse.StatusCode, err
	}
	resultat, err := lireEntete(corps)
	if err != nil {
		return resultatDNS{}, reponse.StatusCode, err
	}
	return resultat, reponse.StatusCode, nil
}

// interrogerReference interroge le résolveur du contrôleur en DNS classique
// (TCP, EDNS0/DO) : c'est la vérité de référence pour la justesse. Le nom
// testé n'est jamais journalisé, seulement comparé en mémoire.
func interrogerReference(adresse, nom string) (resultatDNS, error) {
	requete, err := requeteA(nom)
	if err != nil {
		return resultatDNS{}, err
	}
	conn, err := net.DialTimeout("tcp", adresse, 5*time.Second)
	if err != nil {
		return resultatDNS{}, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	trame := make([]byte, 2+len(requete))
	binary.BigEndian.PutUint16(trame[0:2], uint16(len(requete)))
	copy(trame[2:], requete)
	if _, err := conn.Write(trame); err != nil {
		return resultatDNS{}, err
	}
	var taille [2]byte
	if _, err := io.ReadFull(conn, taille[:]); err != nil {
		return resultatDNS{}, err
	}
	n := int(binary.BigEndian.Uint16(taille[:]))
	if n < 12 || n > 65535 {
		return resultatDNS{}, errReponseDNS
	}
	reponse := make([]byte, n)
	if _, err := io.ReadFull(conn, reponse); err != nil {
		return resultatDNS{}, err
	}
	return lireEntete(reponse)
}

// urlNoeud construit l'URL DoH d'un nœud. Une adresse .onion nue est acceptée.
func urlNoeud(adresse string) (string, error) {
	adresse = strings.TrimSpace(adresse)
	if adresse == "" || strings.ContainsAny(adresse, "/ \t\r\n") {
		return "", errReponseDNS
	}
	if strings.HasPrefix(adresse, "http://") {
		u, err := url.Parse(adresse)
		if err != nil || u.Host == "" {
			return "", errReponseDNS
		}
		adresse = u.Host
	}
	return "http://" + adresse + "/dns-query", nil
}
