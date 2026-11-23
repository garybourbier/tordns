#!/usr/bin/env bash
# shellcheck disable=SC1112
# Preuves de la mission 8 : nœud installable en une commande.
#
# Installation réelle dans un bac à sable jetable (racine temporaire) sur le
# Docker de cette machine : identité générée par Tor, DoH par le .onion
# d'instance, page d'état, idempotence, désinstallation qui garde les clés.
#
# NON PROUVÉ ici : installation des paquets Docker (apt) et activation
# systemd, qui exigent un Debian vierge et root ; les analyses correspondantes
# sont seulement relues. Voir la sortie finale.
set -euo pipefail

RACINE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d /tmp/tordns-m08.XXXXXX)"
BAC="$TMP/bac"

nettoyer() {
    if [ -f "$BAC/opt/tordns/.env" ]; then
        (cd "$BAC/opt/tordns/noeud" && docker compose --env-file "$BAC/opt/tordns/.env" \
            --profile test down --remove-orphans >/dev/null 2>&1) || true
    fi
    docker image rm tordns/noeud-tor:local tordns/etat:local >/dev/null 2>&1 || true
    rm -rf "$TMP"
}
trap nettoyer EXIT

echo "== 1. Scripts portables et compose valide =="
SH_BIN=$(command -v dash || command -v sh)
"$SH_BIN" -n "$RACINE/noeud/installer.sh"
"$SH_BIN" -n "$RACINE/noeud/desinstaller.sh"
echo "installer.sh et desinstaller.sh : syntaxe POSIX acceptée par $SH_BIN."
if grep -nE '\[\[|^[[:space:]]*local |^[[:space:]]*function ' \
    "$RACINE/noeud/installer.sh" "$RACINE/noeud/desinstaller.sh"; then
    echo "ÉCHEC : construction bash dans un script POSIX." >&2
    exit 1
fi

TORDNS_DONNEES=/tmp/tordns-donnees-bidon \
    docker compose -f "$RACINE/noeud/docker-compose.yml" config >"$TMP/compose.txt"
echo "docker compose config : OK ($(grep -c '^    mem_limit:' "$TMP/compose.txt") services à mémoire bornée)."
TOTAL_MEM=$(grep -oE 'mem_limit: "[0-9]+"' "$TMP/compose.txt" |
    grep -oE '[0-9]+' | awk '{s += $1} END {print s + 0}')
[ "$TOTAL_MEM" -le $((1024 * 1024 * 1024)) ] || {
    echo "ÉCHEC : mémoire bornée totale $TOTAL_MEM octets > 1 Gio." >&2
    exit 1
}
grep -q 'cpus:' "$TMP/compose.txt" || {
    echo "ÉCHEC : aucun plafond CPU." >&2
    exit 1
}
echo "Ressources bornées : ${TOTAL_MEM} octets de mémoire max au total (<= 1 Gio), CPU plafonné."

echo
echo "== 2. Aucun secret ni adresse .onion dans le dépôt =="
if git -C "$RACINE" ls-files | grep -E '(^|/)(\.env|hostname|hs_ed25519_(secret|public)_key)$|\.onion$'; then
    echo "ÉCHEC : fichier sensible suivi par git." >&2
    exit 1
fi
# Les fixtures des clients utilisent des adresses d'une seule lettre répétée
# (« aaa…onion ») : elles sont synthétiques et sans secret. Toute autre adresse
# de 56 caractères serait une vraie adresse et ferait échouer la preuve.
if git -C "$RACINE" grep -nE '[a-z2-7]{56}\.onion' -- . ':!docs' ':!*.md' |
    grep -vE '([a-z2-7])\1{55}\.onion'; then
    echo "ÉCHEC : adresse .onion réelle dans le code." >&2
    exit 1
fi
echo "Aucun fichier de clé, .env ou .onion suivi par git."

echo
echo "== 3. Installation dans un bac à sable Debian jetable =="
mkdir -p "$BAC/etc" "$BAC/proc"
cat >"$BAC/etc/os-release" <<'EOF'
ID=debian
VERSION_ID="12"
PRETTY_NAME="Debian GNU/Linux 12 (bookworm) — fixture de test"
EOF
printf 'MemTotal:        2048000 kB\n' >"$BAC/proc/meminfo"

# Les lignes de progression de docker compose (création des conteneurs,
# réseaux, volumes) sont du bruit : seuls les messages de l'installeur sont
# conservés. pipefail propage une éventuelle erreur de l'installeur.
"$SH_BIN" "$RACINE/noeud/installer.sh" \
    --racine "$BAC" --utilisateur "$(id -un)" \
    --sans-docker --sans-systemd 2>&1 |
    grep -vE '^ (Container|Network|Volume|Image) ' | tee "$TMP/installation.txt"

grep -q 'Debian 12' "$TMP/installation.txt" || { echo "ÉCHEC : OS non vérifié." >&2; exit 1; }
grep -q '2000 Mo de RAM' "$TMP/installation.txt" || { echo "ÉCHEC : RAM non vérifiée." >&2; exit 1; }
grep -q 'Adresse .onion d’instance' "$TMP/installation.txt" || { echo "ÉCHEC : adresse non affichée." >&2; exit 1; }
[ "$(stat -c %a "$BAC/var/lib/tordns")" = 700 ] || { echo "ÉCHEC : /var/lib/tordns pas en 0700." >&2; exit 1; }
[ -x "$BAC/usr/local/bin/tordns-adresse" ] || { echo "ÉCHEC : commande tordns-adresse absente." >&2; exit 1; }
[ -f "$BAC/etc/systemd/system/tordns.service" ] || { echo "ÉCHEC : unité systemd absente." >&2; exit 1; }
grep -q 'ExecStart=.*compose .*up -d' "$BAC/etc/systemd/system/tordns.service" || {
    echo "ÉCHEC : unité systemd incomplète." >&2
    exit 1
}
grep -q 'HiddenServiceVersion 3' "$BAC/var/lib/tordns/torrc"
grep -q 'SocksPort 0' "$BAC/var/lib/tordns/torrc"
echo "Installation : OS et RAM vérifiés, dossier 0700, unité systemd, torrc."

ADRESSE=$("$BAC/usr/local/bin/tordns-adresse" | tr -d '\r\n')
printf '%s' "$ADRESSE" | grep -Eq '^[a-z2-7]{56}\.onion$' || {
    echo "ÉCHEC : adresse d'instance invalide : $ADRESSE" >&2
    exit 1
}
echo "Adresse .onion d'instance publiée par Tor : $ADRESSE"

echo
echo "== 4. Relance : idempotence et clés intactes =="
CLE="$BAC/var/lib/tordns/tor/hidden_service/hs_ed25519_secret_key"
EMPREINTE_AVANT=$(sha256sum "$CLE" | awk '{print $1}')
"$SH_BIN" "$RACINE/noeud/installer.sh" \
    --racine "$BAC" --utilisateur "$(id -un)" \
    --sans-docker --sans-systemd --sans-attente >"$TMP/relance.txt" 2>&1
EMPREINTE_APRES=$(sha256sum "$CLE" | awk '{print $1}')
ADRESSE_APRES=$("$BAC/usr/local/bin/tordns-adresse" | tr -d '\r\n')
[ "$EMPREINTE_AVANT" = "$EMPREINTE_APRES" ] || { echo "ÉCHEC : clé modifiée par la relance." >&2; exit 1; }
[ "$ADRESSE" = "$ADRESSE_APRES" ] || { echo "ÉCHEC : adresse changée par la relance." >&2; exit 1; }
echo "Deuxième installation : clé identique ($EMPREINTE_AVANT), adresse identique."

echo
echo "== 5. Préparation Onionbalance (--maitresse) =="
MAITRESSE="$(printf 'a%.0s' $(seq 1 56)).onion"
"$SH_BIN" "$RACINE/noeud/installer.sh" \
    --racine "$BAC" --utilisateur "$(id -un)" --maitresse "$MAITRESSE" \
    --sans-docker --sans-systemd --sans-attente >"$TMP/maitresse.txt" 2>&1
grep -q 'HiddenServiceOnionbalanceInstance 1' "$BAC/var/lib/tordns/torrc"
grep -q "MasterOnionAddress $MAITRESSE" "$BAC/var/lib/tordns/tor/hidden_service/ob_config"
[ "$(sha256sum "$CLE" | awk '{print $1}')" = "$EMPREINTE_AVANT" ] || {
    echo "ÉCHEC : --maitresse a modifié la clé d'instance." >&2
    exit 1
}
echo "ob_config et HiddenServiceOnionbalanceInstance écrits, clé inchangée."
# Retour à un nœud d'instance simple, toujours sans toucher aux clés.
"$SH_BIN" "$RACINE/noeud/installer.sh" \
    --racine "$BAC" --utilisateur "$(id -un)" \
    --sans-docker --sans-systemd --sans-attente >"$TMP/retour.txt" 2>&1
[ ! -f "$BAC/var/lib/tordns/tor/hidden_service/ob_config" ] || { echo "ÉCHEC : ob_config non retiré." >&2; exit 1; }
echo "Relance sans --maitresse : préparation retirée, clé toujours intacte."

echo
echo "== 6. DoH et page d'état par le .onion d'instance =="
(cd "$BAC/opt/tordns/noeud" && docker compose --env-file "$BAC/opt/tordns/.env" \
    --profile test up -d --build tor-client >/dev/null 2>&1)

# Requête DNS example.com A, ID 0x1234, récursion demandée.
printf '\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01' \
    >"$TMP/requete.bin"

joignable=0
for _ in $(seq 1 60); do
    if docker exec tordns-noeud-tor-client \
        curl -s -o /dev/null --max-time 5 \
        --socks5-hostname 127.0.0.1:9050 "http://$ADRESSE/healthz" 2>/dev/null; then
        joignable=1
        break
    fi
    sleep 3
done
[ "$joignable" -eq 1 ] || {
    echo "ÉCHEC : le .onion n'est pas joignable après 180 s." >&2
    (cd "$BAC/opt/tordns/noeud" && docker compose --env-file "$BAC/opt/tordns/.env" logs --tail 20 tor) >&2 || true
    exit 1
}
echo "Service caché joignable par un client Tor séparé."

# Le corps binaire voyage par l'entrée standard du conteneur et la réponse
# revient par sa sortie standard : aucun fichier écrit dans le conteneur.
CODE_DOH=$(docker exec -i tordns-noeud-tor-client \
    curl -s -o /dev/null -w '%{http_code}' --max-time 15 \
    --socks5-hostname 127.0.0.1:9050 \
    -H 'content-type: application/dns-message' \
    --data-binary @- \
    "http://$ADRESSE/dns-query" <"$TMP/requete.bin")
[ "$CODE_DOH" = 200 ] || { echo "ÉCHEC : DoH HTTP $CODE_DOH." >&2; exit 1; }
docker exec -i tordns-noeud-tor-client \
    curl -s --max-time 15 --socks5-hostname 127.0.0.1:9050 \
    -H 'content-type: application/dns-message' --data-binary @- \
    "http://$ADRESSE/dns-query" <"$TMP/requete.bin" >"$TMP/reponse.bin"
ID_REPONSE=$(od -An -tx1 -N2 "$TMP/reponse.bin" | tr -d ' \n')
[ "$ID_REPONSE" = 1234 ] || { echo "ÉCHEC : ID DNS $ID_REPONSE (attendu 1234)." >&2; exit 1; }
RCODE=$(od -An -tu1 -j3 -N1 "$TMP/reponse.bin" | tr -d ' \n')
[ $((RCODE & 15)) -eq 0 ] || { echo "ÉCHEC : RCODE $((RCODE & 15))." >&2; exit 1; }
echo "DoH par le .onion : HTTP 200, $(wc -c <"$TMP/reponse.bin") octets, ID 1234 conservé, RCODE 0."

docker exec tordns-noeud-tor-client \
    curl -s --max-time 15 --socks5-hostname 127.0.0.1:9050 \
    "http://$ADRESSE/.well-known/tordns/etat" >"$TMP/etat.json"
cat "$TMP/etat.json"
grep -q '"logiciel":"TorDNS"' "$TMP/etat.json" || { echo "ÉCHEC : page d'état sans logiciel." >&2; exit 1; }
grep -q "\"version\":\"$(tr -d ' \n' <"$RACINE/noeud/VERSION")\"" "$TMP/etat.json" || {
    echo "ÉCHEC : version absente de la page d'état." >&2
    exit 1
}
grep -q '"unbound":"ok"' "$TMP/etat.json" || { echo "ÉCHEC : Unbound non signalé ok." >&2; exit 1; }
grep -q '"tor":"ok"' "$TMP/etat.json" || { echo "ÉCHEC : Tor non signalé ok." >&2; exit 1; }
grep -Eq '"charge":"(faible|moyenne|forte)"' "$TMP/etat.json" || { echo "ÉCHEC : charge absente." >&2; exit 1; }
if grep -qiE 'requete|domaine|client|compteur' "$TMP/etat.json"; then
    echo "ÉCHEC : la page d'état expose un compteur ou une donnée de client." >&2
    exit 1
fi
echo "Page d'état : version, Unbound ok, Tor ok, charge grossière, aucun compteur."

echo
echo "== 7. Désinstallation : les clés restent =="
"$SH_BIN" "$RACINE/noeud/desinstaller.sh" --racine "$BAC" --sans-systemd \
    2>&1 | tee "$TMP/desinstallation.txt"
[ ! -d "$BAC/opt/tordns" ] || { echo "ÉCHEC : /opt/tordns encore présent." >&2; exit 1; }
[ ! -e "$BAC/usr/local/bin/tordns-adresse" ] || { echo "ÉCHEC : tordns-adresse encore présent." >&2; exit 1; }
[ -f "$CLE" ] || { echo "ÉCHEC : les clés ont été supprimées." >&2; exit 1; }
[ "$(sha256sum "$CLE" | awk '{print $1}')" = "$EMPREINTE_AVANT" ] || {
    echo "ÉCHEC : clé modifiée à la désinstallation." >&2
    exit 1
}
grep -q 'clés et état conservés' "$TMP/desinstallation.txt" || { echo "ÉCHEC : message de conservation absent." >&2; exit 1; }
if docker ps --format '{{.Names}}' | grep -q '^tordns-noeud'; then
    echo "ÉCHEC : des conteneurs du nœud tournent encore." >&2
    exit 1
fi
echo "Code, service et conteneurs retirés ; clés conservées et intactes."

echo
echo "== 8. Suppression des clés : confirmation tapée obligatoire =="
set +e
printf 'non\n' | "$SH_BIN" "$RACINE/noeud/desinstaller.sh" --racine "$BAC" \
    --supprimer-cles --sans-systemd >"$TMP/refus.txt" 2>&1
refus_code=$?
set -e
[ "$refus_code" -ne 0 ] || { echo "ÉCHEC : confirmation incorrecte acceptée." >&2; exit 1; }
[ -f "$CLE" ] || { echo "ÉCHEC : clés supprimées malgré le refus." >&2; exit 1; }
echo "Confirmation incorrecte refusée (code $refus_code), clés intactes."

printf 'SUPPRIMER\n' | "$SH_BIN" "$RACINE/noeud/desinstaller.sh" --racine "$BAC" \
    --supprimer-cles --sans-systemd >"$TMP/suppression.txt" 2>&1
[ ! -d "$BAC/var/lib/tordns" ] || { echo "ÉCHEC : clés encore présentes après confirmation." >&2; exit 1; }
grep -q 'clés et état supprimés' "$TMP/suppression.txt"
echo "Confirmation « SUPPRIMER » : clés et état supprimés."

echo
echo "Mission 8 : toutes les preuves exécutables ici sont passées."
echo "NON PROUVÉ : installation des paquets Docker par apt, activation réelle de"
echo "systemd et exécution dans un conteneur/VM Debian vierge (aucun root ni"
echo "Debian jetable disponible ici). Le nœud a été installé dans une racine"
echo "temporaire jetable sur le Docker de cette machine, avec de vraies clés Tor,"
echo "un vrai .onion et un vrai DoH. Onionbalance, les mises à jour et les autres"
echo "nœuds ne font pas partie de cette mission."
