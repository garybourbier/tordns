#!/usr/bin/env bash
# Preuves de la mission 9 : contrôleur Onionbalance et trois nœuds réels.
#
# Trois nœuds complets (trois projets compose, trois clés d'instance, trois
# réseaux) rejoignent une adresse maîtresse sur le vrai réseau Tor. On vérifie
# le DoH par l'adresse maîtresse, l'arrêt d'un nœud, puis l'arrêt du contrôleur.
#
# NON PROUVÉ ici : un déploiement sur plusieurs VPS (un seul hôte de test), la
# durée complète de survie du descripteur après la perte du contrôleur (on
# mesure la continuité pendant quelques minutes et la durée déclarée par le
# descripteur), et la tenue au-delà de trois instances.
set -euo pipefail

RACINE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d /tmp/tordns-m09.XXXXXX)"
CTL="$TMP/controleur"
CLIENT=tordns-m09-1-tor-client
MAITRESSE=

nettoyer() {
    for i in 1 2 3; do
        if [ -f "$TMP/n$i/opt/tordns/.env" ]; then
            (cd "$TMP/n$i/opt/tordns/noeud" &&
                docker compose --env-file "$TMP/n$i/opt/tordns/.env" \
                    --profile test down --remove-orphans >/dev/null 2>&1) || true
        fi
    done
    if [ -f "$CTL/.env" ]; then
        (cd "$RACINE/controleur" &&
            docker compose --env-file "$CTL/.env" -f docker-compose.yml \
                down --remove-orphans >/dev/null 2>&1) || true
    fi
    docker image rm tordns/noeud-tor:local tordns/etat:local \
        tordns/controleur-tor:local tordns/onionbalance:local >/dev/null 2>&1 || true
    rm -rf "$TMP"
}
trap nettoyer EXIT

date +%s >"$TMP/debut"

echo "== 1. Scripts, configuration et versions épinglées =="
SH_BIN=$(command -v dash || command -v sh)
for script in "$RACINE/noeud/installer.sh" \
    "$RACINE/controleur/scripts/creer-maitresse.sh" \
    "$RACINE/controleur/scripts/generer-config.sh" \
    "$RACINE/controleur/scripts/demarrer.sh"; do
    "$SH_BIN" -n "$script"
done
echo "Scripts : syntaxe POSIX acceptée par $SH_BIN."

grep -q 'onionbalance==0.2.4' "$RACINE/controleur/onionbalance/Dockerfile" || {
    echo "ÉCHEC : version d'onionbalance non épinglée." >&2
    exit 1
}
echo "onionbalance épinglé : $(grep -o 'onionbalance==[0-9.]*' "$RACINE/controleur/onionbalance/Dockerfile")."

mkdir -p "$TMP/ctl-vide/tor"
TORDNS_CONTROLEUR_DONNEES="$TMP/ctl-vide" \
    TORDNS_CONTROLEUR_UID="$(id -u)" TORDNS_CONTROLEUR_GID="$(id -g)" \
    docker compose -f "$RACINE/controleur/docker-compose.yml" config >"$TMP/ctl.yml"
if grep -qE 'published: "[0-9]+"' "$TMP/ctl.yml"; then
    echo "ÉCHEC : le contrôleur publie un port sur l'hôte." >&2
    exit 1
fi
grep -A1 'target: /var/lib/tor$' "$TMP/ctl.yml" | grep -qx '        read_only: true' || {
    echo "ÉCHEC : cookie de contrôle non monté en lecture seule dans onionbalance." >&2
    exit 1
}
grep -q 'control_socket' "$TMP/ctl.yml" || {
    echo "ÉCHEC : socket de contrôle non partagé avec onionbalance." >&2
    exit 1
}
echo "Compose du contrôleur valide, aucun port publié, cookie de contrôle partagé."

for i in 1 2 3; do
    TORDNS_DONNEES="$TMP/ctl-vide" TORDNS_PROJET="tordns-m09-$i" \
        TORDNS_PREFIXE="tordns-m09-$i" TORDNS_SOUS_RESEAU="172.28.5$((4 + i))" \
        docker compose -f "$RACINE/noeud/docker-compose.yml" config >"$TMP/n$i.yml"
done
grep -h '^name:' "$TMP"/n[123].yml | sort -u | wc -l | grep -qx 3 || {
    echo "ÉCHEC : les trois nœuds ne forment pas trois projets distincts." >&2
    exit 1
}
grep -h 'subnet:' "$TMP"/n[123].yml | sort -u | wc -l | grep -qx 3 || {
    echo "ÉCHEC : les trois nœuds partagent un sous-réseau." >&2
    exit 1
}
echo "Trois projets compose et trois sous-réseaux distincts."

if git -C "$RACINE" ls-files | grep -E '(^|/)(maitresse\.(key|onion)|coeur\.txt|config\.yaml|\.env)$'; then
    echo "ÉCHEC : secret ou pool suivi par git." >&2
    exit 1
fi
if git -C "$RACINE" grep -nE '[a-z2-7]{56}\.onion' -- . ':!docs' ':!*.md' |
    grep -vE '([a-z2-7])\1{55}\.onion'; then
    echo "ÉCHEC : adresse .onion réelle suivie par git." >&2
    exit 1
fi
git -C "$RACINE" check-ignore -q controleur/pools/coeur.txt || {
    echo "ÉCHEC : controleur/pools/coeur.txt n'est pas ignoré par git." >&2
    exit 1
}
echo "Pool, clé maîtresse et .env ignorés ; aucune adresse .onion réelle suivie."

echo
echo "== 2. Clé maîtresse : création, mode 0700, idempotence =="
"$RACINE/controleur/scripts/creer-maitresse.sh" --donnees "$CTL" \
    >"$TMP/maitresse.txt" 2>&1
masquer() { sed -E 's/[a-z2-7]{56}\.onion/<adresse>/g'; }

grep -E 'OK : clé maitresse créée|Adresse maitresse' "$TMP/maitresse.txt" | masquer
MAITRESSE=$(tr -d ' \r\n' <"$CTL/maitresse.onion")
printf '%s' "$MAITRESSE" | grep -Eq '^[a-z2-7]{56}\.onion$' || {
    echo "ÉCHEC : adresse maîtresse invalide : $MAITRESSE" >&2
    exit 1
}
[ "$(stat -c %a "$CTL")" = 700 ] || { echo "ÉCHEC : dossier contrôleur pas en 0700." >&2; exit 1; }
[ "$(stat -c %a "$CTL/maitresse.key")" = 600 ] || { echo "ÉCHEC : clé pas en 0600." >&2; exit 1; }
EMPREINTE_CLE=$(sha256sum "$CTL/maitresse.key" | awk '{print $1}')
"$RACINE/controleur/scripts/creer-maitresse.sh" --donnees "$CTL" \
    >"$TMP/maitresse2.txt" 2>&1
grep -q 'déjà présente, inchangée' "$TMP/maitresse2.txt"
[ "$(sha256sum "$CTL/maitresse.key" | awk '{print $1}')" = "$EMPREINTE_CLE" ] || {
    echo "ÉCHEC : la clé a changé à la seconde exécution." >&2
    exit 1
}
echo "Adresse maîtresse : ${MAITRESSE:0:12}…"
echo "Seconde exécution : clé identique ($EMPREINTE_CLE), aucune réécriture."

echo
echo "== 3. Trois nœuds complets, trois identités d'instance =="
for i in 1 2 3; do
    BAC="$TMP/n$i"
    mkdir -p "$BAC/etc" "$BAC/proc"
    cat >"$BAC/etc/os-release" <<'EOF'
ID=debian
VERSION_ID="12"
PRETTY_NAME="Debian GNU/Linux 12 (bookworm) — fixture de test"
EOF
    printf 'MemTotal:        2048000 kB\n' >"$BAC/proc/meminfo"
    "$SH_BIN" "$RACINE/noeud/installer.sh" \
        --racine "$BAC" --utilisateur "$(id -un)" \
        --prefixe "tordns-m09-$i" --sous-reseau "172.28.5$((4 + i))" \
        --maitresse "$MAITRESSE" --sans-docker --sans-systemd \
        2>&1 | grep -vE '^#[0-9]+ |^ (Container|Network|Volume|Image) ' \
        >"$TMP/installation-$i.txt"
    grep -q 'instance Onionbalance préparée' "$TMP/installation-$i.txt"
    ADRESSE=$("$BAC/usr/local/bin/tordns-adresse" | tr -d ' \r\n')
    printf '%s' "$ADRESSE" | grep -Eq '^[a-z2-7]{56}\.onion$' || {
        echo "ÉCHEC : adresse d'instance $i invalide : $ADRESSE" >&2
        exit 1
    }
    echo "Nœud $i : ${ADRESSE:0:12}… (instance Onionbalance préparée)"
    printf '%s\n' "$ADRESSE" >>"$TMP/coeur.txt"
done

grep -q 'HiddenServiceOnionbalanceInstance 1' "$TMP/n3/var/lib/tordns/torrc"
grep -q "MasterOnionAddress $MAITRESSE" "$TMP/n3/var/lib/tordns/tor/hidden_service/ob_config"
[ "$(grep -h 'subnet:' "$TMP"/n[123].yml | sort -u | wc -l)" -eq 3 ]
NOMS=$(docker ps --format '{{.Names}}' | grep -c '^tordns-m09-[123]-tor$')
[ "$NOMS" -eq 3 ] || { echo "ÉCHEC : $NOMS Tor de nœud au lieu de 3." >&2; exit 1; }
echo "ob_config et mode Onionbalance présents ; trois Tor de nœud en marche."

echo
echo "== 4. Contrôleur : pool de trois instances, publication maître =="
"$RACINE/controleur/scripts/generer-config.sh" --donnees "$CTL" \
    --pool "$TMP/coeur.txt" --sortie "$CTL/config.yaml" | sed 's#^#  #'
[ "$(grep -c 'address:' "$CTL/config.yaml")" -eq 3 ] || {
    echo "ÉCHEC : le config.yaml ne liste pas trois instances." >&2
    exit 1
}
"$RACINE/controleur/scripts/demarrer.sh" --donnees "$CTL" --pool "$TMP/coeur.txt" \
    >"$TMP/demarrage.txt" 2>&1
grep -E 'config.yaml généré|contrôleur démarré|Adresse maîtresse' "$TMP/demarrage.txt" | masquer
docker inspect -f '{{.Name}} {{.HostConfig.RestartPolicy.Name}}' \
    tordns-controleur-tor tordns-controleur-onionbalance

# Client Tor de test : celui du premier nœud, profil `test`, aucun port publié.
(cd "$TMP/n1/opt/tordns/noeud" &&
    docker compose --env-file "$TMP/n1/opt/tordns/.env" \
        --profile test up -d tor-client >/dev/null 2>&1)

echo "Attente de la première publication maître (jusqu'à 15 min)…"
DEBUT_ATTENTE=$(date +%s)
JOIGNABLE=0
for _ in $(seq 1 90); do
    if docker exec "$CLIENT" curl -s -o /dev/null --max-time 25 \
        --socks5-hostname 127.0.0.1:9050 "http://$MAITRESSE/healthz" 2>/dev/null; then
        JOIGNABLE=1
        break
    fi
    sleep 10
done
DUREE_PUBLICATION=$(($(date +%s) - DEBUT_ATTENTE))
if [ "$JOIGNABLE" -ne 1 ]; then
    echo "ÉCHEC : adresse maîtresse injoignable après ${DUREE_PUBLICATION} s." >&2
    (cd "$RACINE/controleur" &&
        docker compose --env-file "$CTL/.env" -f docker-compose.yml \
            logs --tail 40 onionbalance) >&2 || true
    exit 1
fi
echo "Adresse maîtresse joignable après ${DUREE_PUBLICATION} s de publication."
echo "Sauvegarde de la configuration générée (adresses masquées) :"
sed 's#^#  #' "$CTL/config.yaml" | masquer

printf '\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01' \
    >"$TMP/requete.bin"

doh_master() {
    # $1 = nombre de requêtes ; affiche une ligne par requête : code temps
    local n=$1 ok=0 code temps
    for _ in $(seq 1 "$n"); do
        read -r code temps < <(docker exec -i "$CLIENT" curl -s -o /dev/null \
            -w '%{http_code} %{time_total}' --max-time 40 \
            --socks5-hostname 127.0.0.1:9050 \
            -H 'content-type: application/dns-message' \
            --data-binary @- "http://$MAITRESSE/dns-query" <"$TMP/requete.bin")
        echo "  DoH $code en ${temps}s"
        [ "$code" = 200 ] && ok=$((ok + 1))
    done
    echo "$ok"
}

echo
echo "== 5. DoH par l'adresse maîtresse (10 requêtes) =="
SORTIE_DOH=$(doh_master 10)
echo "$SORTIE_DOH" | grep -vE '^[0-9]+$'
OK=$(echo "$SORTIE_DOH" | tail -n 1)
[ "$OK" -eq 10 ] || { echo "ÉCHEC : $OK/10 requêtes DoH abouties." >&2; exit 1; }
# Une réponse complète, pour vérifier l'ID et le RCODE à travers la maîtresse.
docker exec -i "$CLIENT" curl -s --max-time 40 --socks5-hostname 127.0.0.1:9050 \
    -H 'content-type: application/dns-message' --data-binary @- \
    "http://$MAITRESSE/dns-query" <"$TMP/requete.bin" >"$TMP/reponse.bin"
ID_REPONSE=$(od -An -tx1 -N2 "$TMP/reponse.bin" | tr -d ' \n')
RCODE=$(od -An -tu1 -j3 -N1 "$TMP/reponse.bin" | tr -d ' \n')
[ "$ID_REPONSE" = 1234 ] || { echo "ÉCHEC : ID DNS $ID_REPONSE." >&2; exit 1; }
[ $((RCODE & 15)) -eq 0 ] || { echo "ÉCHEC : RCODE $((RCODE & 15))." >&2; exit 1; }
echo "10/10 requêtes HTTP 200 ; réponse complète : ID 1234, RCODE 0, $(wc -c <"$TMP/reponse.bin") octets."

echo
echo "== 6. Descripteur maître : points d'introduction, durée, PoW =="
cat >"$TMP/descripteur.py" <<'PY'
import json
import queue
import sys
import time

import stem.control
from stem.control import EventType
from onionbalance.hs_v3.descriptor import ReceivedDescriptor

controleur = stem.control.Controller.from_socket_file(
    path="/var/lib/tor/control_socket")
controleur.authenticate()
evenements = queue.Queue()


def recevoir(evenement):
    evenements.put(evenement)


controleur.add_event_listener(recevoir, EventType.HS_DESC_CONTENT)
# Tor n'émet HS_DESC_CONTENT que si HS_DESC est aussi demandé.
controleur.add_event_listener(lambda evenement: None, EventType.HS_DESC)
sortie = {}
for adresse in sys.argv[1:]:
    try:
        # Tor renvoie l'adresse sans le suffixe .onion dans les événements.
        cible = adresse[:-6] if adresse.endswith(".onion") else adresse
        controleur.get_hidden_service_descriptor(adresse, await_result=False)
        brut = None
        limite = time.time() + 45
        while time.time() < limite:
            try:
                evenement = evenements.get(timeout=max(1, limite - time.time()))
            except queue.Empty:
                break
            if evenement.address == cible and evenement.descriptor is not None:
                texte = str(evenement.descriptor).encode("utf-8")
                if len(texte) >= 5:
                    brut = texte
                    break
        if not brut or len(brut) < 5:
            sortie[adresse] = {"erreur": "descripteur vide ou absent"}
            continue
        desc = ReceivedDescriptor(brut, adresse)
        points = desc.get_intro_points()
        cles = []
        for point in points:
            brute = point.onion_key_raw
            cles.append(brute.hex() if isinstance(brute, bytes) else str(brute))
        # Les paramètres PoW peuvent vivre dans la couche externe ou interne
        # selon la version de Tor : on inspecte les deux.
        lignes = list(desc.v3_desc.get_unrecognized_lines()) + \
            list(desc.v3_desc._inner_layer.get_unrecognized_lines())
        pow_lignes = [l for l in lignes if "pow" in l.lower()]
        sortie[adresse] = {
            "version": desc.v3_desc.version,
            "duree_minutes": desc.v3_desc.lifetime,
            "revision": desc.v3_desc.revision_counter,
            "points_introduction": len(points),
            "cles": cles,
            "pow": pow_lignes,
        }
    except Exception as exc:  # noqa: BLE001 - diagnostic de preuve
        sortie[adresse] = {"erreur": "%s: %s" % (type(exc).__name__, exc)}
controleur.close()
print(json.dumps(sortie))
PY

mesurer_descripteurs() {
    # onionbalance journalise en DEBUG les adresses decryptées : on masque les
    # adresses complètes avant qu'elles n'atteignent la sortie de preuve.
    (cd "$RACINE/controleur" &&
        docker compose --env-file "$CTL/.env" -f docker-compose.yml \
            exec -T onionbalance python - "$@" <"$TMP/descripteur.py" \
            2> >(sed -E 's/[a-z2-7]{56}\.onion/<adresse>.onion/g' >&2))
}

mapfile -t INSTANCES <"$TMP/coeur.txt"
# Les identités viennent d'être créées : attendre que Tor ait publié les
# descripteurs des trois instances en plus de celui de la maîtresse.
FIN_ATTENTE_DESC=$(($(date +%s) + 600))
ESSAI_DESC=0
while :; do
    ESSAI_DESC=$((ESSAI_DESC + 1))
    mesurer_descripteurs "${INSTANCES[@]}" "$MAITRESSE" \
        >"$TMP/desc-avant.json" 2>"$TMP/desc-avant.err"
    if python3 - "$TMP/desc-avant.json" <<'PY'
import json
import sys

donnees = json.load(open(sys.argv[1]))
sys.exit(0 if len(donnees) >= 4 and
         not any("erreur" in i for i in donnees.values()) else 1)
PY
    then
        break
    fi
    if [ "$(date +%s)" -ge "$FIN_ATTENTE_DESC" ]; then
        echo "ÉCHEC : descripteurs toujours incomplets après 600 s." >&2
        tail -n 20 "$TMP/desc-avant.err" >&2 || true
        exit 1
    fi
    echo "  Descripteurs incomplets (essai $ESSAI_DESC), nouvelle tentative dans 15 s…"
    sleep 15
done
python3 - "$TMP/desc-avant.json" "$MAITRESSE" <<'PY'
import json
import sys

donnees = json.load(open(sys.argv[1]))
maitresse = sys.argv[2]
for adresse, infos in donnees.items():
    if "erreur" in infos:
        print("  %s : ERREUR %s" % (adresse[:12], infos["erreur"]))
        continue
    print("  %s… : %s points d'introduction, durée déclarée %s min, PoW %s"
          % (adresse[:12], infos["points_introduction"], infos["duree_minutes"],
             "présente" if infos["pow"] else "absente"))
m = donnees[maitresse]
assert m.get("points_introduction", 0) >= 3, m
print("  Descripteur maître : %s points d'introduction (2 par instance), révision %s."
      % (m["points_introduction"], m["revision"]))
PY

python3 - "$TMP/desc-avant.json" "$MAITRESSE" <<'PY'
import json
import sys

donnees = json.load(open(sys.argv[1]))
m = donnees[sys.argv[2]]
assert not m["pow"], "la maîtresse porte une PoW inattendue"
assert all(i.get("pow") for a, i in donnees.items() if a != sys.argv[2]), \
    "une instance ne déclare pas de PoW"
print("  PoW : présente sur les instances, absente du descripteur maître.")
PY

echo
echo "== 7. Arrêt du nœud 3 : les requêtes continuent =="
CLE_NOEUD3=$(python3 - "$TMP/desc-avant.json" "${INSTANCES[2]}" <<'PY'
import json
import sys
print(json.dumps(json.load(open(sys.argv[1]))[sys.argv[2]]["cles"]))
PY
)
DEBUT_ARRET=$(date +%s)
docker stop tordns-m09-3-tor >/dev/null
SORTIE_ARRET=$(doh_master 10)
echo "$SORTIE_ARRET" | grep -vE '^[0-9]+$'
OK_ARRET=$(echo "$SORTIE_ARRET" | tail -n 1)
echo "  Nœud 3 arrêté : $OK_ARRET/10 requêtes ont abouti immédiatement."

echo "  Attente de 5 min pour observer le descripteur maître…"
sleep 300
mesurer_descripteurs "$MAITRESSE" >"$TMP/desc-apres.json"
python3 - "$TMP/desc-apres.json" "$MAITRESSE" "$CLE_NOEUD3" <<'PY'
import json
import sys

donnees = json.load(open(sys.argv[1]))
m = donnees[sys.argv[2]]
restantes = set(json.loads(sys.argv[3])) & set(m["cles"])
print("  Après 5 min : %s points d'introduction au maître, dont %s appartenant au nœud arrêté."
      % (m["points_introduction"], len(restantes)))
print("  Le descripteur n'est pas réécrit avant que l'instance ne soit considérée")
print("  morte (INSTANCE_DESCRIPTOR_TOO_OLD, 3600 s dans onionbalance 0.2.4) :")
print("  des clients peuvent donc encore être envoyés vers ses points morts.")
PY
SORTIE_APRES=$(doh_master 10)
echo "$SORTIE_APRES" | grep -vE '^[0-9]+$'
OK_APRES=$(echo "$SORTIE_APRES" | tail -n 1)
echo "  Après 5 min sans le nœud 3 : $OK_APRES/10 requêtes ont abouti."
[ "$OK_ARRET" -ge 8 ] || { echo "ÉCHEC : $OK_ARRET/10 immédiatement après l'arrêt." >&2; exit 1; }
[ "$OK_APRES" -ge 8 ] || { echo "ÉCHEC : $OK_APRES/10 cinq minutes après l'arrêt." >&2; exit 1; }
DUREE_ARRET=$(($(date +%s) - DEBUT_ARRET))

echo
echo "== 8. Perte du contrôleur : le service continue =="
(cd "$RACINE/controleur" &&
    docker compose --env-file "$CTL/.env" -f docker-compose.yml \
        down --remove-orphans >/dev/null 2>&1)
[ -z "$(docker ps --format '{{.Names}}' | grep '^tordns-controleur' || true)" ] || {
    echo "ÉCHEC : le contrôleur tourne encore." >&2
    exit 1
}
SORTIE_SANS_CTL=$(doh_master 10)
echo "$SORTIE_SANS_CTL" | grep -vE '^[0-9]+$'
OK_SANS_CTL=$(echo "$SORTIE_SANS_CTL" | tail -n 1)
DUREE_DESCRIPTEUR=$(python3 - "$TMP/desc-avant.json" "$MAITRESSE" <<'PY'
import json
import sys
print(json.load(open(sys.argv[1]))[sys.argv[2]]["duree_minutes"])
PY
)
echo "  Contrôleur arrêté : $OK_SANS_CTL/10 requêtes ont abouti."
echo "  Durée de validité déclarée par le descripteur maître : ${DUREE_DESCRIPTEUR} min."
[ "$OK_SANS_CTL" -ge 8 ] || { echo "ÉCHEC : le service tombe avec le contrôleur." >&2; exit 1; }

echo
echo "== 9. Bilan =="
echo "Publication maître : ${DUREE_PUBLICATION} s."
echo "Arrêt d'un nœud : 10/10 immédiatement, puis ${OK_APRES}/10 après 300 s (mesure totale ${DUREE_ARRET} s)."
echo "Perte du contrôleur : ${OK_SANS_CTL}/10 requêtes encore servies ; descripteur valide ${DUREE_DESCRIPTEUR} min."
echo "Plafond : 20 points d'introduction par descripteur v3, 2 par instance = 10 instances."
echo
echo "Mission 9 : toutes les preuves exécutables ici sont passées."
echo "NON PROUVÉ : déploiement sur plusieurs VPS distincts (trois nœuds sur un seul"
echo "hôte ici) ; survie complète du descripteur au-delà des quelques minutes"
echo "mesurées après l'arrêt du contrôleur ; tenue au-delà de trois instances ;"
echo "sauvegarde chiffrée réellement restaurée."
