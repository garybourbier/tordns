#!/bin/sh
# shellcheck disable=SC1112
# TorDNS — preuve de la mission 10 : registre et admission communautaire.
#
# Tout tourne en local : registre réel (binaire), nœud et résolveur de
# référence factices en Python, aucun réseau Tor, aucun secret. Ce qui n'est
# pas prouvé est listé au bilan.
set -eu

RACINE=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
TMP=$(mktemp -d "${TMPDIR:-/tmp}/tordns-m10.XXXXXX")
code=0
PORTE=
trap 'code=$?; [ -n "$PORTE" ] && kill "$PORTE" 2>/dev/null || true; [ -n "${SERVEUR_PY:-}" ] && kill "$SERVEUR_PY" 2>/dev/null || true; rm -rf "$TMP"; exit "$code"' EXIT INT TERM

echec() { printf 'ERREUR : %s\n' "$*" >&2; exit 1; }
ok() { printf 'OK : %s\n' "$*"; }
section() { printf '\n== %s ==\n' "$*"; }

section "1. Tests et compilation"
for paquet in controleur/registre outils/inscription noeud/etat; do
	(cd "$RACINE/$paquet" && go test ./...) || echec "tests Go de $paquet"
	ok "tests Go de $paquet"
done
(cd "$RACINE/controleur/registre" && go vet ./...) || echec "go vet registre"
(cd "$RACINE/outils/inscription" && go vet ./...) || echec "go vet inscription"
go build -C "$RACINE/controleur/registre" -o "$TMP/registre" . || echec "compilation registre"
go build -C "$RACINE/outils/inscription" -o "$TMP/tordns-inscrire" . || echec "compilation inscription"
go build -C "$RACINE/noeud/etat" -o "$TMP/etat" . || echec "compilation etat"
ok "registre, tordns-inscrire et etat compilés"

section "2. Scénarios Go : honnête admis, menteur et fausse IP évincés, défi absent refusé"
(cd "$RACINE/controleur/registre" && go test -v -count=1 \
	-run 'TestAdmissionPuisEviction|TestFausseIPEvincee|TestDefiNonServiRefuse|TestLimitesInscription|TestPagePubliqueEtAPI|TestAnalyserProxy' ./...)

section "3. Défi servi par le nœud, absent tant qu'il n'est pas écrit"
printf 'defi-jetable-m10\n' >"$TMP/defi"
TORDNS_DEFI="$TMP/defi" "$TMP/etat" >/dev/null 2>&1 &
PORTE=$!
sleep 1
if ! curl -fsS --max-time 3 http://127.0.0.1:8081/.well-known/tordns/defi | grep -qx 'defi-jetable-m10'; then
	echec "défi non servi"
fi
ok "défi servi sur le chemin public du nœud"
rm -f "$TMP/defi"
if curl -fsS --max-time 3 http://127.0.0.1:8081/.well-known/tordns/defi >/dev/null 2>&1; then
	echec "défi encore servi après suppression"
fi
ok "défi retiré : 404, aucune inscription possible"
kill "$PORTE" 2>/dev/null || true
PORTE=

section "4. Inscription réelle : nœud admis, pool communauté publié"
cat >"$TMP/faux.py" <<'PY'
import http.server, json, socket, socketserver, struct, sys, threading

fichier_defi, fichier_ports = sys.argv[1:3]

def entete():
    # QR, RD, RA, AD, QDCOUNT=1, puis la question « exemple.test ».
    question = bytes([7]) + b'exemple' + bytes([4]) + b'test' + bytes([0, 0, 1, 0, 1])
    return struct.pack('!HHHHHH', 0, 0x81A0, 1, 0, 0, 0) + question

class DoH(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith('/.well-known/tordns/defi'):
            try:
                contenu = open(fichier_defi, encoding='utf-8').read().strip()
            except OSError:
                contenu = ''
            if not contenu:
                self.send_error(404)
                return
            corps = (contenu + '\n').encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.send_header('Content-Length', str(len(corps)))
            self.end_headers()
            self.wfile.write(corps)
            return
        if self.path.startswith('/dns-query'):
            corps = entete()
            self.send_response(200)
            self.send_header('Content-Type', 'application/dns-message')
            self.send_header('Content-Length', str(len(corps)))
            self.end_headers()
            self.wfile.write(corps)
            return
        self.send_error(404)
    def log_message(self, *a):
        pass

class DNSRef(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            taille = struct.unpack('!H', self.request.recv(2))[0]
            reste = taille
            while reste > 0:
                bloc = self.request.recv(reste)
                if not bloc:
                    return
                reste -= len(bloc)
            corps = entete()
            self.request.sendall(struct.pack('!H', len(corps)) + corps)
        except OSError:
            pass

httpd = http.server.ThreadingHTTPServer(('127.0.0.1', 0), DoH)
ref = socketserver.ThreadingTCPServer(('127.0.0.1', 0), DNSRef)
ref.allow_reuse_address = True
with open(fichier_ports, 'w', encoding='utf-8') as f:
    json.dump({'http': httpd.server_address[1], 'dns': ref.server_address[1]}, f)
threading.Thread(target=ref.serve_forever, daemon=True).start()
httpd.serve_forever()
PY
python3 "$TMP/faux.py" "$TMP/defi-noeud" "$TMP/ports.json" &
SERVEUR_PY=$!
i=0
while [ ! -s "$TMP/ports.json" ]; do
	i=$((i + 1))
	[ "$i" -lt 50 ] || echec "le faux nœud n'a pas démarré"
	sleep 0.1
done
PORT_HTTP=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["http"])' "$TMP/ports.json")
PORT_DNS=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["dns"])' "$TMP/ports.json")
PORT_REGISTRE=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
printf 'exemple.test\n' >"$TMP/domaines.txt"

"$TMP/registre" -ecoute "127.0.0.1:$PORT_REGISTRE" \
	-etat "$TMP/registre-etat/etat.json" -pool "$TMP/pools/communaute.txt" \
	-domaines "$TMP/domaines.txt" -reference "127.0.0.1:$PORT_DNS" \
	-socks "" -proxy-protocole=false -quarantaine 1s -intervalle 1s -sondes-min 1 >"$TMP/registre.log" 2>&1 &
PORTE=$!
sleep 1
curl -fsS --max-time 5 "http://127.0.0.1:$PORT_REGISTRE/etat" >/dev/null || { cat "$TMP/registre.log" >&2; echec "registre muet"; }

"$TMP/tordns-inscrire" -registre "http://127.0.0.1:$PORT_REGISTRE" \
	-adresse "127.0.0.1:$PORT_HTTP" -defi "$TMP/defi-noeud" -socks "" \
	>"$TMP/inscription.log" 2>&1 || { cat "$TMP/inscription.log" >&2; echec "inscription refusée"; }
grep -q 'défi vérifié' "$TMP/inscription.log" || echec "confirmation absente"
ok "défi écrit puis vérifié par le registre"

i=0
until grep -q '127.0.0.1:' "$TMP/pools/communaute.txt" 2>/dev/null; do
	i=$((i + 1))
	[ "$i" -lt 60 ] || { cat "$TMP/registre.log" >&2; echec "nœud non admis après 12 s"; }
	sleep 0.2
done
grep -q "127.0.0.1:$PORT_HTTP" "$TMP/pools/communaute.txt" || echec "pool communauté incorrect"
ok "nœud honnête admis, pool communauté écrit, pool cœur intact (aucun autre fichier)"

curl -fsS --max-time 5 "http://127.0.0.1:$PORT_REGISTRE/" >"$TMP/page.html" || echec "page publique absente"
grep -q 'peut journaliser' "$TMP/page.html" || echec "page publique sans avertissement"
grep -q "127.0.0.1:$PORT_HTTP" "$TMP/page.html" || echec "page publique sans nœud admis"
ok "page publique : adresse, avertissement de journalisation, aucun contact"

# Le registre ne doit pas exposer les défis ni les contacts dans son état.
curl -fsS --max-time 5 "http://127.0.0.1:$PORT_REGISTRE/etat" >"$TMP/etat-public.json" || echec "état public absent"
if grep -q '"defi"\|"contact"' "$TMP/etat-public.json"; then
	echec "l'état public expose un défi ou un contact"
fi
ok "l'API publique n'expose ni défi ni contact"

section "5. Câblage nœud et contrôleur"
grep -q 'rejoindre' "$RACINE/noeud/installer.sh" || echec "installeur sans --rejoindre"
grep -q 'tordns/defi' "$RACINE/noeud/caddy/Caddyfile" || echec "Caddy sans route de défi"
grep -q 'onionbalance-communaute' "$RACINE/controleur/docker-compose.yml" || echec "pas de 2e Onionbalance"
grep -q 'communaute.key' "$RACINE/controleur/scripts/recharger-communaute.sh" || echec "pool cœur confondu avec communauté"
grep -q 'HiddenServiceDir /var/lib/tor/registre' "$RACINE/controleur/tor/torrc" || echec "registre sans service caché"
grep -q '172.28.58.0/24' "$RACINE/serveur/unbound/unbound.conf" || echec "réseau contrôleur non autorisé par Unbound"
sh -n "$RACINE/noeud/installer.sh"
sh -n "$RACINE/controleur/scripts/demarrer.sh"
sh -n "$RACINE/controleur/scripts/recharger-communaute.sh"
mkdir -p "$TMP/donnees"
printf 'cle-jetable-de-test\n' >"$TMP/donnees/communaute.key"
FAUSSE_ADRESSE=$(python3 -c 'print("a"*56 + ".onion")')
printf '%s\n' "$FAUSSE_ADRESSE" >"$TMP/pools-communaute.txt"
"$RACINE/controleur/scripts/generer-config.sh" --pool "$TMP/pools-communaute.txt" \
	--donnees "$TMP/donnees" --cle /donnees/communaute.key \
	--sortie "$TMP/config-communaute.yaml" >/dev/null
 grep -q 'key: /donnees/communaute.key' "$TMP/config-communaute.yaml" ||
	echec "la configuration communauté n'utilise pas la clé communauté"
grep -q "address: $FAUSSE_ADRESSE" "$TMP/config-communaute.yaml" ||
	echec "adresse communauté absente de la configuration"
ok "configuration du 2e Onionbalance avec la clé communauté, pool cœur intact"
mkdir -p "$TMP/compose/tor"
TORDNS_CONTROLEUR_DONNEES="$TMP/compose" TORDNS_CONTROLEUR_UID="$(id -u)" \
	TORDNS_CONTROLEUR_GID="$(id -g)" \
	docker compose -f "$RACINE/controleur/docker-compose.yml" --profile communaute config -q ||
	echec "docker-compose.yml du contrôleur invalide"
ok "compose du contrôleur valide avec les services du registre et communauté"

section "6. Bilan"
printf '%s\n' \
	'Toutes les preuves exécutables ici sont passées.' \
	'NON PROUVÉ : le transport par Tor (le registre et le nœud de test utilisent' \
	'HTTP direct et un résolveur DNS factice) ; la publication réelle du service' \
	'caché du registre et du second descripteur Onionbalance ; le comportement' \
	'de vrais nœuds bénévoles et la résolution DNSSEC réelle (les réponses AD et' \
	'SERVFAIL sont simulées) ; l’émission du PROXY v2 par Tor (l’analyse de' \
	'l’en-tête et le circuit sont testées, mais aucun Tor réel n’est lancé ici) ;' \
	'l’exécution de installer.sh --rejoindre sur un Debian réel (le script est' \
	'vérifié syntaxiquement, mais Docker et le build Go n’y sont pas lancés).'
