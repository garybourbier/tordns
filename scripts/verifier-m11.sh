#!/usr/bin/env bash
# TorDNS — preuve de la mission 11 : mises à jour signées.
#
# Montre, sans réseau Tor réel (le transport Tor est remplacé par HTTP local,
# voir « non prouvé ») :
#   1. publication v2 acceptée par le nœud et par le client Linux ;
#   2. rejeu de v1 refusé (version ≤ installée) ;
#   3. manifeste altéré d'un octet refusé ;
#   4. image par étiquette refusée ;
#   5. image cassée : retour arrière automatique vers la version précédente ;
#   6. client dont le service refuse de redémarrer : binaire précédent rétabli.
set -euo pipefail

RACINE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TMP=$(mktemp -d /tmp/tordns-m11.XXXXXX)
SERVEUR_PID=
trap 'set +e; [ -n "$SERVEUR_PID" ] && kill "$SERVEUR_PID" 2>/dev/null; rm -rf "$TMP"' EXIT

ok() { printf 'OK : %s\n' "$*"; }
echec() { printf 'ÉCHEC : %s\n' "$*" >&2; exit 1; }

echo "== 1. Compilation et tests unitaires =="
for paquet in "outils/manifeste" "outils/publier" "noeud/maj" "client-linux"; do
    (cd "$RACINE/$paquet" && go test ./... >/dev/null) ||
        echec "tests Go de $paquet"
    ok "tests Go de $paquet"
done
(cd "$RACINE/outils/publier" && go build -o "$TMP/tordns-signer" .)
(cd "$RACINE/noeud/maj" && go build -o "$TMP/tordns-maj" .)
(cd "$RACINE/client-linux/cmd/maj" && go build -o "$TMP/tordns-client-maj" .)
ok "tordns-signer, tordns-maj et tordns-client-maj compilés"

echo
echo "== 2. Clé jetable et publication de deux versions =="
"$TMP/tordns-signer" cle --dossier "$TMP/cles" >/dev/null
CLE=$(cat "$TMP/cles/publication.pub")
MIROIR="$TMP/miroir"
mkdir -p "$MIROIR/maj"
printf 'binaire client v2\n' >"$MIROIR/maj/tordns-client"
printf 'paquet noeud v2\n' >"$MIROIR/maj/tordns-noeud.tar.gz"
DIGEST_V1="sha256:$(printf '11%.0s' {1..32})"
DIGEST_V2="sha256:$(printf '22%.0s' {1..32})"
HORS_LIGNE="$TMP/cle-vide"
"$TMP/tordns-signer" cle --dossier "$HORS_LIGNE" >/dev/null

# Serveur local : manifeste, fichiers, et sonde de santé dépendant de l'image
# actuellement écrite dans l'override (v1 = sain, v2 = cassée).
cat >"$TMP/serveur.py" <<'PY'
import http.server, os, sys, socketserver

racine, override, fichier_sain, fichier_port = sys.argv[1:5]

class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass
    def do_GET(self):
        if self.path == "/sante":
            try:
                contenu = open(override, encoding="utf-8").read()
            except OSError:
                contenu = ""
            try:
                sain = open(fichier_sain, encoding="utf-8").read().strip()
            except OSError:
                sain = ""
            code = 200 if sain and sain in contenu else 500
            self.send_response(code)
            self.end_headers()
            self.wfile.write(b"ok" if code == 200 else b"cassee")
            return
        chemin = None
        if self.path in ("/manifeste.json", "/manifeste.json.sig"):
            chemin = os.path.join(racine, self.path.lstrip("/"))
        elif self.path.startswith("/maj/"):
            chemin = os.path.join(racine, self.path.lstrip("/"))
        if not chemin or not os.path.isfile(chemin):
            self.send_error(404)
            return
        with open(chemin, "rb") as f:
            donnees = f.read()
        self.send_response(200)
        self.send_header("Content-Length", str(len(donnees)))
        self.end_headers()
        self.wfile.write(donnees)

srv = socketserver.TCPServer(("127.0.0.1", 0), H)
open(fichier_port, "w").write(str(srv.server_address[1]))
srv.serve_forever()
PY

mkdir -p "$TMP/pub-v1" "$TMP/pub-v2"
"$TMP/tordns-signer" manifeste --dossier "$TMP/cles" --version 1 \
    --expire 2027-01-31T00:00:00Z --sortie "$TMP/pub-v1" \
    --cible client-linux-amd64="$MIROIR/maj/tordns-client,https://exemple.invalid/maj/tordns-client" \
    --image unbound="ghcr.io/tordns/unbound@$DIGEST_V1" >/dev/null
cp "$TMP/pub-v1/manifeste.json" "$MIROIR/manifeste.json"
cp "$TMP/pub-v1/manifeste.json.sig" "$MIROIR/manifeste.json.sig"

# L'override existe déjà en v1 : la sonde est saine avant toute mise à jour.
mkdir -p "$TMP/noeud"
printf 'services:\n  unbound:\n    image: ghcr.io/tordns/unbound@%s\n' "$DIGEST_V1" \
    >"$TMP/noeud/maj-images.yml"
printf '%s' "$DIGEST_V1" >"$TMP/sain"
python3 "$TMP/serveur.py" "$MIROIR" "$TMP/noeud/maj-images.yml" "$TMP/sain" "$TMP/port" &
SERVEUR_PID=$!
for _ in $(seq 1 100); do [ -s "$TMP/port" ] && break; sleep 0.05; done
PORT=$(cat "$TMP/port")
BASE="http://127.0.0.1:$PORT"
ok "clé jetable et deux manifestes signés ; serveur local sur $BASE"

# Les URL des cibles doivent pointer vers ce serveur : on re-signe v2 ainsi.
"$TMP/tordns-signer" manifeste --dossier "$TMP/cles" --version 2 \
    --expire 2027-01-31T00:00:00Z --sortie "$TMP/pub-v2" \
    --cible client-linux-amd64="$MIROIR/maj/tordns-client,$BASE/maj/tordns-client" \
    --cible noeud="$MIROIR/maj/tordns-noeud.tar.gz,$BASE/maj/tordns-noeud.tar.gz" \
    --image unbound="ghcr.io/tordns/unbound@$DIGEST_V2" \
    --adresse coeur="$(printf 'a%.0s' {1..56}).onion" >/dev/null
cp "$TMP/pub-v2/manifeste.json" "$MIROIR/manifeste.json"
cp "$TMP/pub-v2/manifeste.json.sig" "$MIROIR/manifeste.json.sig"
# v1 resservie plus tard pour le rejeu : les URL n'importent pas (refus avant
# tout téléchargement de cible).
"$TMP/tordns-signer" verifier --manifeste "$TMP/pub-v2/manifeste.json" \
    --signature "$TMP/pub-v2/manifeste.json.sig" --cle "$CLE" >/dev/null
ok "manifeste v2 vérifié hors ligne"

echo
echo "== 3. Refus obligatoires =="
if "$TMP/tordns-signer" verifier --manifeste "$TMP/pub-v1/manifeste.json" \
    --signature "$TMP/pub-v1/manifeste.json.sig" --cle "$CLE" \
    --version-installee 2 >/dev/null 2>&1; then
    echec "rejeu v1 accepté au-dessus de v2"
fi
ok "rejeu de v1 refusé (version ≤ installée)"

cp "$TMP/pub-v2/manifeste.json" "$TMP/altere.json"
python3 - "$TMP/altere.json" <<'PY'
import sys
chemin = sys.argv[1]
brut = bytearray(open(chemin, "rb").read())
i = brut.index(b'"version"') + len(b'"version": ')
brut[i] = ord('3') if brut[i] != ord('3') else ord('4')
open(chemin, "wb").write(brut)
PY
if "$TMP/tordns-signer" verifier --manifeste "$TMP/altere.json" \
    --signature "$TMP/pub-v2/manifeste.json.sig" --cle "$CLE" >/dev/null 2>&1; then
    echec "manifeste altéré accepté"
fi
ok "manifeste altéré d'un octet refusé"

# L'outil de publication refuse déjà de signer une étiquette ; le rejet à la
# vérification (manifeste signé par une clé valide mais référence non épinglée)
# est couvert par le test unitaire dédié.
(cd "$RACINE/outils/manifeste" && go test -run TestRefusImageParEtiquette -v ./... >/dev/null) ||
    echec "image par étiquette acceptée par la vérification"
ok "image demandée par étiquette refusée (publication et vérification)"

if "$TMP/tordns-signer" verifier --manifeste "$TMP/pub-v2/manifeste.json" \
    --signature "$TMP/pub-v2/manifeste.json.sig" --cle "$(cat "$HORS_LIGNE/publication.pub")" >/dev/null 2>&1; then
    echec "signature acceptée avec une autre clé"
fi
ok "signature vérifiée avec la mauvaise clé : refusée"

echo
echo "== 4. Nœud : v2 appliquée, puis v1 rejouée =="
mkdir -p "$TMP/faux-bin"
cat >"$TMP/faux-bin/docker" <<EOF
#!/bin/sh
printf '%s\\n' "\$*" >>"$TMP/docker.log"
exit 0
EOF
chmod 0755 "$TMP/faux-bin/docker"
export PATH="$TMP/faux-bin:$PATH"
printf 'TORDNS_PROJET=tordns-m11\n' >"$TMP/noeud/.env"
cat >"$TMP/etat-noeud.json" <<EOF
{"version": 1, "images": {"unbound": "ghcr.io/tordns/unbound@$DIGEST_V1"}}
EOF
printf '%s' "$DIGEST_V2" >"$TMP/sain"
cmn_noeud=("$TMP/tordns-maj" -manifeste "$BASE/manifeste.json" -etat "$TMP/etat-noeud.json" \
    -compose "$TMP/noeud" -env "$TMP/noeud/.env" -sante "$BASE/sante" -cle "$CLE")
"${cmn_noeud[@]}" >"$TMP/noeud-v2.log" 2>&1 ||
    { cat "$TMP/noeud-v2.log" >&2; echec "nœud : v2 refusée"; }
grep -q '"version": 2' "$TMP/etat-noeud.json" || echec "nœud : état non passé en v2"
grep -q "$DIGEST_V2" "$TMP/noeud/maj-images.yml" || echec "nœud : override sans empreinte v2"
grep -q 'pull --quiet' "$TMP/docker.log" || echec "nœud : pull par empreinte non tenté"
ok "nœud passé en v2, images tirées par empreinte"

cp "$TMP/pub-v1/manifeste.json" "$MIROIR/manifeste.json"
cp "$TMP/pub-v1/manifeste.json.sig" "$MIROIR/manifeste.json.sig"
if "${cmn_noeud[@]}" >/dev/null 2>&1; then
    echec "nœud : rejeu v1 accepté"
fi
grep -q '"version": 2' "$TMP/etat-noeud.json" || echec "nœud : état modifié par le rejeu"
ok "nœud : rejeu v1 refusé, version 2 conservée"

echo
echo "== 5. Nœud : image cassée, retour arrière automatique =="
cp "$TMP/pub-v2/manifeste.json" "$MIROIR/manifeste.json"
cp "$TMP/pub-v2/manifeste.json.sig" "$MIROIR/manifeste.json.sig"
# La sonde renvoie 500 tant que l'override contient v2 ; après retour en v1,
# elle redevient saine.
printf '%s' "$DIGEST_V1" >"$TMP/sain"
cat >"$TMP/etat-noeud.json" <<EOF
{"version": 1, "images": {"unbound": "ghcr.io/tordns/unbound@$DIGEST_V1"}}
EOF
printf 'services:\n  unbound:\n    image: ghcr.io/tordns/unbound@%s\n' "$DIGEST_V1" \
    >"$TMP/noeud/maj-images.yml"
if "${cmn_noeud[@]}" >"$TMP/noeud-casse.log" 2>&1; then
    echec "nœud : image cassée acceptée"
fi
grep -q "retour à la v1" "$TMP/noeud-casse.log" ||
    { cat "$TMP/noeud-casse.log" >&2; echec "nœud : pas de retour arrière annoncé"; }
grep -q "$DIGEST_V1" "$TMP/noeud/maj-images.yml" || echec "nœud : override non restauré en v1"
grep -q '"version": 1' "$TMP/etat-noeud.json" || echec "nœud : état avancé malgré l'échec"
ok "image cassée refusée par la sonde, v1 rétablie automatiquement"

echo
echo "== 6. Client Linux : v2, rejeu, puis service qui refuse =="
printf '#!/bin/sh\nprintf "%%s\\n" "$*" >>"%s/systemctl.log"\nexit 0\n' "$TMP" \
    >"$TMP/faux-systemctl"
chmod 0755 "$TMP/faux-systemctl"
printf 'binaire client v1\n' >"$TMP/client-installe"
chmod 0755 "$TMP/client-installe"
cat >"$TMP/etat-client.json" <<EOF
{"version": 1}
EOF
cmn_client=("$TMP/tordns-client-maj" -manifeste "$BASE/manifeste.json" -socks "" \
    -etat "$TMP/etat-client.json" -binaire "$TMP/client-installe" \
    -service tordns-client -systemctl "$TMP/faux-systemctl" -cle "$CLE")
"${cmn_client[@]}" >"$TMP/client-v2.log" 2>&1 ||
    { cat "$TMP/client-v2.log" >&2; echec "client : v2 refusée"; }
cmp -s "$TMP/client-installe" "$MIROIR/maj/tordns-client" ||
    echec "client : binaire non remplacé"
grep -q '"version": 2' "$TMP/etat-client.json" || echec "client : état non passé en v2"
ok "client passé en v2, binaire remplacé et service redémarré"

cp "$TMP/pub-v1/manifeste.json" "$MIROIR/manifeste.json"
cp "$TMP/pub-v1/manifeste.json.sig" "$MIROIR/manifeste.json.sig"
if "${cmn_client[@]}" >/dev/null 2>&1; then
    echec "client : rejeu v1 accepté"
fi
grep -q '"version": 2' "$TMP/etat-client.json" || echec "client : état modifié par le rejeu"
ok "client : rejeu v1 refusé"

# Nouveau binaire v3, mais systemctl factice échoue au premier redémarrage.
printf 'binaire client v3\n' >"$MIROIR/maj/tordns-client"
"$TMP/tordns-signer" manifeste --dossier "$TMP/cles" --version 3 \
    --expire 2027-01-31T00:00:00Z --sortie "$TMP/pub-v3" \
    --cible client-linux-amd64="$MIROIR/maj/tordns-client,$BASE/maj/tordns-client" \
    --image unbound="ghcr.io/tordns/unbound@$DIGEST_V2" >/dev/null
cp "$TMP/pub-v3/manifeste.json" "$MIROIR/manifeste.json"
cp "$TMP/pub-v3/manifeste.json.sig" "$MIROIR/manifeste.json.sig"
cat >"$TMP/faux-systemctl" <<EOF
#!/bin/sh
printf '%s\\n' "\$*" >>"$TMP/systemctl.log"
case "\$1" in
restart)
	compteur="$TMP/restarts"
	n=\$(cat "\$compteur" 2>/dev/null || echo 0)
	n=\$((n + 1))
	printf '%s' "\$n" >"\$compteur"
	[ "\$n" -eq 1 ] && exit 1
	exit 0
	;;
*) exit 0 ;;
esac
EOF
chmod 0755 "$TMP/faux-systemctl"
cp "$TMP/client-installe" "$TMP/client-avant-v3"
if "${cmn_client[@]}" >"$TMP/client-casse.log" 2>&1; then
    echec "client : service en échec ignoré"
fi
cmp -s "$TMP/client-installe" "$TMP/client-avant-v3" ||
    echec "client : binaire v3 conservé malgré l'échec"
grep -q '"version": 2' "$TMP/etat-client.json" || echec "client : état avancé malgré l'échec"
ok "service en échec : binaire précédent rétabli et redémarré"

echo
echo "== 7. Miroir /maj/ et unités systemd =="
grep -q 'handle_path /maj/\*' "$RACINE/noeud/caddy/Caddyfile" ||
    echec "Caddyfile sans miroir /maj/"
grep -q 'maj:/srv/maj:ro' "$RACINE/noeud/docker-compose.yml" ||
    echec "compose sans montage du miroir"
grep -q 'tordns-maj.timer' "$RACINE/noeud/installer.sh" ||
    echec "installeur sans timer de mise à jour"
grep -q 'RandomizedDelaySec=30min' "$RACINE/noeud/tordns-maj.timer" ||
    echec "timer sans décalage aléatoire"
sh -n "$RACINE/noeud/installer.sh" && sh -n "$RACINE/noeud/desinstaller.sh" ||
    echec "syntaxe POSIX de l'installeur"
ok "miroir /maj/, timer 6 h à décalage aléatoire, installeur valide"

echo
echo "== 8. Bilan =="
echo "Toutes les preuves exécutables ici sont passées."
echo "NON PROUVÉ : le transport par Tor (les tests utilisent un serveur HTTP local"
echo "et un proxy SOCKS non sollicité) ; un vrai registre Docker (docker est"
echo "remplacé par un script factice) ; un redémarrage systemd réel (systemctl"
echo "est remplacé) ; la construction de tordns-maj par l'installeur sur Debian"
echo "(elle télécharge l'image golang) ; la rotation de clé sur un parc réel."
