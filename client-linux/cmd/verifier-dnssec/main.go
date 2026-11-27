// tordns-verifier-dnssec — diagnostic DNSSEC contre un nom réel (Mission 28).
//
// Le client valide déjà DNSSEC ses réponses, mais tous ses tests utilisent des
// fixtures en mémoire : rien ne prouvait la chaîne contre la vraie racine. Cet
// outil interroge un résolveur DoH choisi par l'appelant, puis applique la
// même validation que le relais (ancres IANA compilées, DS/DNSKEY, RRSIG).
//
// Vie privée : le nom demandé est envoyé au résolveur DoH indiqué, en clair
// pour lui (HTTPS protège le trajet, pas le destinataire). Cet outil est un
// diagnostic d'audit, pas le chemin normal du client : TorDNS résout via Tor.
// Aucun nom n'est journalisé par l'outil lui-même.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"tordns/client-linux/relais"
)

const tailleMaxReponse = 64 << 10

func main() {
	doh := flag.String("doh", "", "URL DoH du résolveur d'audit (obligatoire, ex. https://cloudflare-dns.com/dns-query)")
	delai := flag.Duration("delai", 10*time.Second, "délai maximal de la requête DoH")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(),
			"usage : %s -doh URL nom\n\n", os.Args[0])
		fmt.Fprintln(flag.CommandLine.Output(),
			"Valide DNSSEC la réponse A de « nom » contre les ancres racine IANA.")
		fmt.Fprintln(flag.CommandLine.Output(),
			"Le nom est envoyé au résolveur DoH indiqué : diagnostic d'audit uniquement.")
		flag.PrintDefaults()
	}
	flag.Parse()
	if *doh == "" || flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	nom := flag.Arg(0)

	client := &http.Client{Timeout: *delai}
	interroger := func(paquet []byte) ([]byte, error) {
		return posterDoH(client, *doh, paquet)
	}

	err := relais.ValiderNom(nom, interroger)
	switch {
	case err == nil:
		fmt.Printf("verdict : accepté DNSSEC — %s\n", nom)
	case errors.Is(err, relais.ErrZoneNonSignee):
		fmt.Printf("verdict : zone non signée (délégation sans DS) — %s\n", nom)
		fmt.Println("Le mode auto l'accepte sans garantie DNSSEC ; le mode strict la refuse.")
	default:
		fmt.Printf("verdict : REFUSÉ — %s : %v\n", nom, err)
		os.Exit(1)
	}
}

// posterDoH envoie une requête DNS brute en POST (RFC 8484) et rend la
// réponse. La taille est bornée et le code HTTP vérifié.
func posterDoH(client *http.Client, url string, paquet []byte) ([]byte, error) {
	ctx, annuler := context.WithTimeout(context.Background(), client.Timeout)
	defer annuler()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(paquet))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	rep, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("DoH %s : %w", url, err)
	}
	defer rep.Body.Close()
	if rep.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH %s : code HTTP %d", url, rep.StatusCode)
	}
	corps, err := io.ReadAll(io.LimitReader(rep.Body, tailleMaxReponse+1))
	if err != nil {
		return nil, fmt.Errorf("DoH %s : lecture : %w", url, err)
	}
	if len(corps) > tailleMaxReponse {
		return nil, errors.New("réponse DoH trop grosse")
	}
	return corps, nil
}
