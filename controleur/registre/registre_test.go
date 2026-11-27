package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// reponseFactice construit un en-tête DNS valide : QR + RD + RA, qd=1.
func reponseFactice(rcode uint16, ad bool) []byte {
	brut := make([]byte, 12)
	binary.BigEndian.PutUint16(brut[0:2], 0)
	drapeaux := uint16(0x8000 | 0x0100 | 0x0080 | rcode)
	if ad {
		drapeaux |= 0x0020
	}
	binary.BigEndian.PutUint16(brut[2:4], drapeaux)
	binary.BigEndian.PutUint16(brut[4:6], 1)
	// Question « exemple.test » : le parseur lit la section question.
	question := []byte{7, 'e', 'x', 'e', 'm', 'p', 'l', 'e', 4, 't', 'e', 's', 't', 0, 0, 1, 0, 1}
	return append(brut, question...)
}

// reponseA construit une réponse avec les adresses A fournies.
func reponseA(rcode uint16, ad bool, ips ...string) []byte {
	brut := reponseFactice(rcode, ad)
	binary.BigEndian.PutUint16(brut[6:8], uint16(len(ips)))
	for _, ip := range ips {
		adresse := net.ParseIP(ip).To4()
		if adresse == nil {
			panic("adresse IPv4 de test invalide")
		}
		reponse := []byte{0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4}
		reponse = append(reponse, adresse...)
		brut = append(brut, reponse...)
	}
	return brut
}

// reponseFausseA renvoie AD=1 mais une adresse inventée : c'est exactement le
// mensonge qu'une comparaison du seul bit AD laisserait passer.
func reponseFausseA() []byte {
	return reponseA(0, true, "203.0.113.9")
}

type fauxNoeud struct {
	serveur  *httptest.Server
	defi     atomic.Value
	fixe     atomic.Value
	menteur  atomic.Bool
	fausseIP atomic.Bool
}

func nouveauFauxNoeud(t *testing.T) *fauxNoeud {
	t.Helper()
	n := &fauxNoeud{}
	n.defi.Store("")
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/tordns/defi", func(w http.ResponseWriter, r *http.Request) {
		defi, _ := n.defi.Load().(string)
		if defi == "" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(defi + "\n"))
	})
	mux.HandleFunc("/dns-query", func(w http.ResponseWriter, r *http.Request) {
		if v := n.fixe.Load(); v != nil {
			w.Header().Set("Content-Type", "application/dns-message")
			_, _ = w.Write(v.([]byte))
			return
		}
		if n.menteur.Load() {
			// Réponse signée correcte mais sans AD : mensonge DNSSEC.
			w.Header().Set("Content-Type", "application/dns-message")
			_, _ = w.Write(reponseFactice(0, false))
			return
		}
		if n.fausseIP.Load() {
			// AD=1 et une adresse inventée : la comparaison des A doit refuser.
			w.Header().Set("Content-Type", "application/dns-message")
			_, _ = w.Write(reponseFausseA())
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(reponseFactice(0, true))
	})
	n.serveur = httptest.NewServer(mux)
	t.Cleanup(n.serveur.Close)
	return n
}

func (n *fauxNoeud) adresse() string { return strings.TrimPrefix(n.serveur.URL, "http://") }

// nouveauFauxReference ouvre un résolveur DNS TCP minimal qui répond toujours
// NOERROR + AD : la référence des tests.
func nouveauFauxReference(t *testing.T) string {
	t.Helper()
	return nouveauFauxReferenceAvec(t, reponseFactice(0, true))
}

func nouveauFauxReferenceAvec(t *testing.T, rep []byte) string {
	t.Helper()
	ecoute, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ecoute.Close() })
	go func() {
		for {
			conn, err := ecoute.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				var taille [2]byte
				if _, err := io.ReadFull(c, taille[:]); err != nil {
					return
				}
				q := make([]byte, binary.BigEndian.Uint16(taille[:]))
				if _, err := io.ReadFull(c, q); err != nil {
					return
				}
				binary.BigEndian.PutUint16(taille[:], uint16(len(rep)))
				_, _ = c.Write(append(taille[:], rep...))
			}(conn)
		}
	}()
	return ecoute.Addr().String()
}

func registreDeTest(t *testing.T) (*registre, string, string) {
	t.Helper()
	dir := t.TempDir()
	reference := nouveauFauxReference(t)
	cfg := config{
		AdressesLocales:     true,
		Quarantaine:         time.Microsecond,
		SondesMin:           1,
		EchecsMax:           1,
		IndispoMax:          2,
		MaxInscriptionsJour: 10,
		MaxParIP:            1,
		Reference:           reference,
		Domaines:            []string{"exemple.test"},
		Client:              &http.Client{Timeout: 2 * time.Second},
	}
	hook := filepath.Join(dir, "hook.log")
	cfg.Hook = func() { _ = os.WriteFile(hook, []byte("ok\n"), 0o600) }
	r, err := nouveauRegistre(filepath.Join(dir, "registre.json"), filepath.Join(dir, "communaute.txt"), cfg)
	if err != nil {
		t.Fatal(err)
	}
	return r, hook, filepath.Join(dir, "communaute.txt")
}

func inscrireEtConfirmer(t *testing.T, r *registre, n *fauxNoeud) {
	t.Helper()
	c, err := r.inscrire(n.adresse(), "", "127.0.0.1")
	if err != nil {
		t.Fatalf("inscription : %v", err)
	}
	n.defi.Store(c.Defi)
	if _, err := r.confirmer(c.Adresse); err != nil {
		t.Fatalf("confirmation : %v", err)
	}
}

func TestAdmissionPuisEviction(t *testing.T) {
	r, hook, pool := registreDeTest(t)
	n := nouveauFauxNoeud(t)
	inscrireEtConfirmer(t, r, n)

	change, err := r.passe()
	if err != nil || !change {
		t.Fatalf("passe : change=%v err=%v", change, err)
	}
	if _, ok := r.instantane().Admis[n.adresse()]; !ok {
		t.Fatal("nœud honnête non admis")
	}
	brut, err := os.ReadFile(pool)
	if err != nil || !strings.Contains(string(brut), n.adresse()) {
		t.Fatalf("pool communauté non écrit : %v %q", err, brut)
	}
	if _, err := os.Stat(hook); err != nil {
		t.Fatalf("hook non appelé : %v", err)
	}

	// Le nœud se met à mentir sur DNSSEC : un seul mensonge suffit.
	n.menteur.Store(true)
	change, err = r.passe()
	if err != nil || !change {
		t.Fatalf("passe menteuse : change=%v err=%v", change, err)
	}
	e := r.instantane()
	if _, ok := e.Admis[n.adresse()]; ok {
		t.Fatal("nœud menteur toujours admis")
	}
	if _, ok := e.Evinces[n.adresse()]; !ok {
		t.Fatal("nœud menteur non évincé")
	}
	brut, _ = os.ReadFile(pool)
	if strings.Contains(string(brut), n.adresse()) {
		t.Fatal("nœud évincé encore dans le pool")
	}
	// Une adresse évincée ne peut pas se réinscrire.
	if _, err := r.inscrire(n.adresse(), "", "127.0.0.2"); err == nil {
		t.Fatal("réinscription d'une adresse évincée acceptée")
	}
}

func TestFausseIPEvincee(t *testing.T) {
	r, _, _ := registreDeTest(t)
	n := nouveauFauxNoeud(t)
	inscrireEtConfirmer(t, r, n)
	if _, err := r.passe(); err != nil {
		t.Fatal(err)
	}
	n.fausseIP.Store(true)
	if _, err := r.passe(); err != nil {
		t.Fatal(err)
	}
	e := r.instantane()
	if _, ok := e.Admis[n.adresse()]; ok {
		t.Fatal("nœud à fausse IP toujours admis")
	}
}

func TestDefiNonServiRefuse(t *testing.T) {
	r, _, _ := registreDeTest(t)
	n := nouveauFauxNoeud(t)
	c, err := r.inscrire(n.adresse(), "", "127.0.0.1")
	if err != nil {
		t.Fatalf("inscription : %v", err)
	}
	if _, err := r.confirmer(c.Adresse); err == nil {
		t.Fatal("défi absent accepté")
	}
	if e := r.instantane(); len(e.Admis) != 0 {
		t.Fatal("nœud sans défi admis")
	}
}

func TestLimitesInscription(t *testing.T) {
	r, _, _ := registreDeTest(t)
	n1 := nouveauFauxNoeud(t)
	inscrireEtConfirmer(t, r, n1)
	n2 := nouveauFauxNoeud(t)
	if _, err := r.inscrire(n2.adresse(), "", "127.0.0.1"); err == nil {
		t.Fatal("seconde inscription de la même source acceptée")
	}
}

func TestPagePubliqueEtAPI(t *testing.T) {
	r, _, _ := registreDeTest(t)
	n := nouveauFauxNoeud(t)
	inscrireEtConfirmer(t, r, n)
	if _, err := r.passe(); err != nil {
		t.Fatal(err)
	}
	s := httptest.NewServer(r.routes())
	defer s.Close()

	rep, err := http.Get(s.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	corps := make([]byte, 16384)
	l, _ := rep.Body.Read(corps)
	rep.Body.Close()
	texte := string(corps[:l])
	if !strings.Contains(texte, n.adresse()) || !strings.Contains(texte, "peut journaliser") {
		t.Fatalf("page publique incomplète : %s", texte)
	}
	if strings.Contains(texte, "contact") {
		t.Fatal("la page expose un contact")
	}

	rep, err = http.Get(s.URL + "/etat")
	if err != nil {
		t.Fatal(err)
	}
	var e etat
	if err := json.NewDecoder(rep.Body).Decode(&e); err != nil {
		t.Fatal(err)
	}
	rep.Body.Close()
	if len(e.Admis) != 1 {
		t.Fatalf("état public : %d admis", len(e.Admis))
	}
	// L'API d'état ne doit pas divulguer les défis des candidats.
	if strings.Contains(mustJSON(t, e), "defi") {
		t.Fatal("l'état public expose un défi")
	}
}

// Relecture du 23/11 : un CDN ou un tourniquet peut renvoyer un autre ensemble
// d'adresses ; seule une intersection vide est suspecte.
func TestSondeTourniquetIntersection(t *testing.T) {
	r, _, _ := registreDeTest(t)
	r.cfg.Reference = nouveauFauxReferenceAvec(t, reponseA(0, true, "192.0.2.1", "192.0.2.2"))
	n := nouveauFauxNoeud(t)
	n.fixe.Store(reponseA(0, true, "192.0.2.2", "192.0.2.3"))
	douteux, err := r.sonder(n.adresse(), []string{"exemple.test"})
	if err != nil || len(douteux) != 0 {
		t.Fatalf("tourniquet refusé : douteux=%v err=%v", douteux, err)
	}
}

func TestAdresseInventeeSurZoneSigneeEstMensonge(t *testing.T) {
	r, _, _ := registreDeTest(t)
	r.cfg.Reference = nouveauFauxReferenceAvec(t, reponseA(0, true, "192.0.2.1"))
	n := nouveauFauxNoeud(t)
	n.fixe.Store(reponseA(0, true, "192.0.2.9"))
	if _, err := r.sonder(n.adresse(), []string{"exemple.test"}); !errors.Is(err, errMensonge) {
		t.Fatalf("adresse inventée acceptée : %v", err)
	}
}

func TestDnssecFailedResoluEstMensonge(t *testing.T) {
	r, _, _ := registreDeTest(t)
	r.cfg.Reference = nouveauFauxReferenceAvec(t, reponseFactice(2, false))
	n := nouveauFauxNoeud(t)
	n.fixe.Store(reponseFactice(0, false))
	if _, err := r.sonder(n.adresse(), []string{"dnssec-failed.org"}); !errors.Is(err, errMensonge) {
		t.Fatalf("dnssec-failed.org résolu accepté : %v", err)
	}
}

// N écarts non signés sur des domaines distincts disqualifient ; en dessous du
// seuil, le candidat reste en quarantaine et n'est pas admis.
func TestDouteuxNEvineQuApresNDomaines(t *testing.T) {
	r, _, _ := registreDeTest(t)
	r.cfg.Reference = nouveauFauxReferenceAvec(t, reponseA(0, false, "192.0.2.1"))
	r.cfg.Domaines = []string{"un.test", "deux.test", "trois.test"}
	r.cfg.DomainesParPasse = 3
	r.cfg.DoutesMax = 4
	n := nouveauFauxNoeud(t)
	n.fixe.Store(reponseA(0, false, "192.0.2.9"))
	inscrireEtConfirmer(t, r, n)

	if _, err := r.passe(); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	c := r.etat.Candidats[n.adresse()]
	if c == nil || len(c.Doutes) != 3 || c.SondesOK != 0 {
		r.mu.Unlock()
		t.Fatalf("doutes mal comptés : %+v", c)
	}
	if len(r.etat.Admis) != 0 {
		r.mu.Unlock()
		t.Fatal("candidat admis malgré les doutes")
	}
	r.mu.Unlock()

	r.cfg.DoutesMax = 3
	if _, err := r.passe(); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.etat.Candidats[n.adresse()]; ok {
		t.Fatal("candidat toujours présent après N domaines distincts")
	}
}

// Un nœud admis qui accumule N doutes non signés sur des domaines distincts
// est évincé, sans attendre un mensonge signé.
func TestDouteuxEvinceUnAdmis(t *testing.T) {
	r, _, _ := registreDeTest(t)
	n := nouveauFauxNoeud(t)
	inscrireEtConfirmer(t, r, n)
	if _, err := r.passe(); err != nil {
		t.Fatal(err)
	}

	r.cfg.Reference = nouveauFauxReferenceAvec(t, reponseA(0, false, "192.0.2.1"))
	r.cfg.Domaines = []string{"un.test", "deux.test", "trois.test"}
	r.cfg.DomainesParPasse = 3
	r.cfg.DoutesMax = 3
	n.fixe.Store(reponseA(0, false, "192.0.2.9"))
	change, err := r.passe()
	if err != nil || !change {
		t.Fatalf("éviction des doutes : change=%v err=%v", change, err)
	}
	e := r.instantane()
	if _, ok := e.Admis[n.adresse()]; ok {
		t.Fatal("nœud douteux toujours admis")
	}
	if _, ok := e.Evinces[n.adresse()]; !ok {
		t.Fatal("nœud douteux non évincé")
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestAnalyserProxy(t *testing.T) {
	circuit := "circuit-jetable"
	bloc := []byte{10, 0, 0, 1, 10, 0, 0, 2, 0x1f, 0x90, 0, 80}
	bloc = append(bloc, 0x05, 0, byte(len(circuit)))
	bloc = append(bloc, circuit...)
	enTete := append([]byte(nil), signatureProxy...)
	enTete = append(enTete, 0x21, 0x11, byte(len(bloc)>>8), byte(len(bloc)))
	enTete = append(enTete, bloc...)

	source, lu, err := analyserProxy(bufio.NewReader(bytes.NewReader(enTete)))
	if err != nil {
		t.Fatal(err)
	}
	if lu != circuit {
		t.Fatalf("circuit = %q", lu)
	}
	tcp, ok := source.(*net.TCPAddr)
	if !ok || !tcp.IP.Equal(net.IPv4(10, 0, 0, 1)) || tcp.Port != 8080 {
		t.Fatalf("source = %#v", source)
	}

	// Sans en-tête (healthcheck local), aucune erreur et aucun circuit.
	source, lu, err = analyserProxy(bufio.NewReader(strings.NewReader("GET /etat HTTP/1.1\r\n\r\n")))
	if err != nil || source != nil || lu != "" {
		t.Fatalf("sans en-tête : source=%v circuit=%q err=%v", source, lu, err)
	}
}

func TestRequeteDNS(t *testing.T) {
	q, err := requeteA("exemple.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(q) < 12 || q[12] != 7 {
		t.Fatalf("requête mal formée : %x", q)
	}
	if _, err := lireEntete(reponseFactice(0, true)); err != nil {
		t.Fatal(err)
	}
	if _, err := lireEntete(reponseFactice(2, false)); err != nil {
		t.Fatal(err)
	}
	res, _ := lireEntete(reponseFactice(2, false))
	if res.Rcode != 2 || res.AD {
		t.Fatalf("en-tête mal lu : %+v", res)
	}
	_ = base64.RawURLEncoding
}

// Relecture Claude du 23/11 : /etat est public ; le contact d'un bénévole et
// le défi d'un candidat n'y figurent jamais (l'ancien test ne regardait l'état
// qu'après admission, quand il n'y avait plus aucun candidat).
func TestEtatPublicSansContactNiDefi(t *testing.T) {
	r, _, _ := registreDeTest(t)
	n := nouveauFauxNoeud(t)
	c, err := r.inscrire(n.adresse(), "benevole@exemple.invalid", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewServer(r.routes())
	defer s.Close()
	rep, err := http.Get(s.URL + "/etat")
	if err != nil {
		t.Fatal(err)
	}
	brut, _ := io.ReadAll(rep.Body)
	rep.Body.Close()
	texte := string(brut)
	if !strings.Contains(texte, n.adresse()) {
		t.Fatalf("candidat absent de l'état : %s", texte)
	}
	if strings.Contains(texte, "benevole@exemple.invalid") || strings.Contains(texte, c.Defi) {
		t.Fatalf("l'état public expose le contact ou le défi : %s", texte)
	}
	// L'état interne, lui, garde le contact (pour joindre le bénévole).
	r.mu.Lock()
	garde := r.etat.Candidats[n.adresse()].Contact
	r.mu.Unlock()
	if garde != "benevole@exemple.invalid" {
		t.Fatalf("contact perdu dans l'état interne : %q", garde)
	}
}

// Relecture du 24/11, point 5a : rappeler confirmer ne doit jamais remettre à zéro
// le compte à rebours de la quarantaine (ici une vraie durée, pas une nanoseconde).
func TestConfirmerRejoueNeRepoussePasLaQuarantaine(t *testing.T) {
	r, _, _ := registreDeTest(t)
	horloge := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	r.cfg.Maintenant = func() time.Time { return horloge }
	r.cfg.Quarantaine = 72 * time.Hour
	n := nouveauFauxNoeud(t)
	inscrireEtConfirmer(t, r, n)
	debut := r.etat.Candidats[n.adresse()].Depuis
	horloge = horloge.Add(48 * time.Hour)
	if _, err := r.confirmer(n.adresse()); err != nil {
		t.Fatalf("seconde confirmation : %v", err)
	}
	if got := r.etat.Candidats[n.adresse()].Depuis; !got.Equal(debut) {
		t.Fatalf("Depuis remis à %v (attendu %v) : admission repoussée par un tiers", got, debut)
	}
	if r.etat.Candidats[n.adresse()].Defi != "" {
		t.Fatal("défi conservé après confirmation")
	}
}

// Point 5b-c : une seule grammaire, et une seule écriture par cible.
func TestNormalisationAdresses(t *testing.T) {
	r, _, _ := registreDeTest(t)
	onion := strings.Repeat("a", 56) + ".onion"
	if a, ok := r.normaliser("  " + strings.ToUpper(onion) + " "); !ok || a != onion {
		t.Fatalf("onion non normalisée : %q %v", a, ok)
	}
	if a, ok := r.normaliser("localhost:080"); !ok || a != "127.0.0.1:80" {
		t.Fatalf("adresse locale non canonique : %q %v", a, ok)
	}
	r.cfg.AdressesLocales = false
	for _, mauvaise := range []string{"127.0.0.1:80", "10.0.0.1:80", "exemple.test:80", onion + ":80"} {
		if _, ok := r.normaliser(mauvaise); ok {
			t.Fatalf("%q accepté hors des bancs de test", mauvaise)
		}
	}
}

// Mission 28, point 3 : la référence DNSSEC du contrôleur est injoignable.
// La faute est imputable au contrôleur : la passe est abandonnée et AUCUN
// compteur du bénévole ne bouge (ni échec, ni date du dernier succès).
func TestReferenceInjoignableNAllereAucunCompteur(t *testing.T) {
	r, _, _ := registreDeTest(t)
	n := nouveauFauxNoeud(t)
	inscrireEtConfirmer(t, r, n)
	if _, err := r.passe(); err != nil {
		t.Fatal(err)
	}
	avant, ok := r.instantane().Admis[n.adresse()]
	if !ok {
		t.Fatal("nœud honnête non admis")
	}

	// La référence ne répond plus : port fermé, échec immédiat.
	r.cfg.Reference = "127.0.0.1:1"
	if _, err := r.passe(); err == nil {
		t.Fatal("passe sans référence : aucune erreur")
	}
	apres, ok := r.instantane().Admis[n.adresse()]
	if !ok {
		t.Fatal("nœud évincé alors que la faute vient du contrôleur")
	}
	if apres.SondesKO != avant.SondesKO || apres.SuiteKO != avant.SuiteKO ||
		apres.SondesOK != avant.SondesOK || !apres.DernierOK.Equal(avant.DernierOK) {
		t.Fatalf("compteurs modifiés par une panne de la référence : avant %+v, après %+v", avant, apres)
	}
}

// Mission 28, point 3 : les échecs consécutifs se remettent à zéro après un
// succès, et IndispoMax évince un nœud durablement injoignable (le compteur
// historique SondesKO, lui, reste pour la disponibilité publiée).
func TestIndisponibilitesConsecutivesPuisEviction(t *testing.T) {
	r, _, _ := registreDeTest(t) // IndispoMax = 2
	n := nouveauFauxNoeud(t)
	inscrireEtConfirmer(t, r, n)
	if _, err := r.passe(); err != nil {
		t.Fatal(err)
	}

	// Réponse inexploitable : le nœud est indisponible, pas le contrôleur.
	n.fixe.Store([]byte("pas un message DNS"))
	if _, err := r.passe(); err != nil {
		t.Fatal(err)
	}
	a, ok := r.instantane().Admis[n.adresse()]
	if !ok {
		t.Fatal("nœud évincé après un seul échec alors que IndispoMax vaut 2")
	}
	if a.SuiteKO != 1 || a.SondesKO != 1 {
		t.Fatalf("échec non compté : %+v", a)
	}

	// Un succès remet les échecs consécutifs à zéro, sans effacer l'historique.
	n.fixe.Store(reponseFactice(0, true))
	if _, err := r.passe(); err != nil {
		t.Fatal(err)
	}
	a, ok = r.instantane().Admis[n.adresse()]
	if !ok {
		t.Fatal("nœud évincé après un succès")
	}
	if a.SuiteKO != 0 {
		t.Fatalf("échecs consécutifs non remis à zéro : %+v", a)
	}
	if a.SondesKO != 1 {
		t.Fatalf("historique d'échecs effacé : %+v", a)
	}

	// Deux échecs consécutifs : éviction et pool mis à jour.
	n.fixe.Store([]byte("pas un message DNS"))
	for i := 0; i < 2; i++ {
		if _, err := r.passe(); err != nil {
			t.Fatal(err)
		}
	}
	e := r.instantane()
	if _, ok := e.Admis[n.adresse()]; ok {
		t.Fatal("nœud injoignable toujours admis après IndispoMax")
	}
	if _, ok := e.Evinces[n.adresse()]; !ok {
		t.Fatal("nœud injoignable non conservé comme évincé")
	}
}

// Mission 28, point 3 : le quota journalier se décompte à la confirmation.
// Une inscription non confirmée ne consomme rien ; la confirmation qui dépasse
// le quota est refusée.
func TestQuotaJournalierALaConfirmation(t *testing.T) {
	r, _, _ := registreDeTest(t)
	r.cfg.MaxInscriptionsJour = 1

	n1 := nouveauFauxNoeud(t)
	inscrireEtConfirmer(t, r, n1)
	if e := r.instantane(); e.TotalJour != 1 {
		t.Fatalf("quota non décompté à la confirmation : %d", e.TotalJour)
	}

	// Une inscription non confirmée ne consomme pas le quota.
	n2 := nouveauFauxNoeud(t)
	c2, err := r.inscrire(n2.adresse(), "", "127.0.0.2")
	if err != nil {
		t.Fatalf("inscription refusée alors que le quota n'est décompté qu'à la confirmation : %v", err)
	}
	if e := r.instantane(); e.TotalJour != 1 {
		t.Fatalf("quota décompté à l'inscription : %d", e.TotalJour)
	}
	n2.defi.Store(c2.Defi)
	if _, err := r.confirmer(c2.Adresse); err == nil {
		t.Fatal("confirmation acceptée au-delà du quota journalier")
	}
}

// Mission 28, point 3 : rétention. Les candidats non confirmés anciens et les
// évincés anciens sont purgés ; les confirmés et les récents restent.
func TestRetentionPurgeCandidatsEtEvinces(t *testing.T) {
	r, _, _ := registreDeTest(t)
	r.cfg.RetentionCandidats = time.Hour
	r.cfg.RetentionEvinces = time.Hour
	maintenant := time.Now().UTC()
	ancien := maintenant.Add(-2 * time.Hour)

	r.etat.Candidats["127.0.0.1:1"] = &candidat{Adresse: "127.0.0.1:1", Depuis: ancien}
	r.etat.Candidats["127.0.0.1:2"] = &candidat{Adresse: "127.0.0.1:2", Depuis: ancien, Confirme: true}
	r.etat.Candidats["127.0.0.1:3"] = &candidat{Adresse: "127.0.0.1:3", Depuis: maintenant}
	r.etat.Evinces["127.0.0.1:4"] = ancien
	r.etat.Evinces["127.0.0.1:5"] = maintenant

	r.changerJour(maintenant)

	e := r.instantane()
	if _, ok := e.Candidats["127.0.0.1:1"]; ok {
		t.Fatal("candidat non confirmé ancien non purgé")
	}
	if _, ok := e.Candidats["127.0.0.1:2"]; !ok {
		t.Fatal("candidat confirmé purgé")
	}
	if _, ok := e.Candidats["127.0.0.1:3"]; !ok {
		t.Fatal("candidat récent purgé")
	}
	if _, ok := e.Evinces["127.0.0.1:4"]; ok {
		t.Fatal("évincé ancien non purgé")
	}
	if _, ok := e.Evinces["127.0.0.1:5"]; !ok {
		t.Fatal("évincé récent purgé")
	}
}

// Mission 28, point 3 : chaque sonde utilise un identifiant DNS aléatoire, que
// le nœud ne peut pas anticiper.
func TestSondeIdentifiantDNSAleatoire(t *testing.T) {
	r, _, _ := registreDeTest(t)
	n := nouveauFauxNoeud(t)
	inscrireEtConfirmer(t, r, n)
	vus := map[uint16]bool{}
	for i := 0; i < 8; i++ {
		_, mesures, err := r.sonderAvecMesures(n.adresse(), []string{"exemple.test"})
		if err != nil {
			t.Fatal(err)
		}
		if len(mesures) != 1 || mesures[0].DnsID == 0 {
			t.Fatalf("identifiant DNS absent de la mesure : %+v", mesures)
		}
		vus[mesures[0].DnsID] = true
	}
	if len(vus) < 2 {
		t.Fatal("identifiant DNS identique à chaque sonde")
	}
}
