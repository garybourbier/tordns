# tordns-signer — publication signée (Mission 11)

Outil hors ligne, sans dépendance hors bibliothèque standard Go, qui crée la
paire Ed25519 de publication, construit le manifeste et vérifie une signature.
Aucune connexion réseau : les fichiers sont signés localement, puis déposés à
la main sur le miroir.

## 1. Créer la clé de publication (une fois, hors du dépôt)

```bash
go build -o tordns-signer ./outils/publier
./tordns-signer cle --dossier ~/tordns-cles
# publication.key (0600, à garder hors ligne) et publication.pub (0644)
```

La clé privée ne doit **jamais** entrer dans le dépôt ni sur un nœud. La clé
publique est compilée dans les programmes :

```bash
CLE=$(cat ~/tordns-cles/publication.pub)
go build -ldflags "-X tordns/manifeste.ClePubliqueEpinglee=$CLE" \
    -o tordns-client ./client-linux
go build -ldflags "-X tordns/manifeste.ClePubliqueEpinglee=$CLE" \
    -o tordns-client-maj ./client-linux/cmd/maj
go build -ldflags "-X tordns/manifeste.ClePubliqueEpinglee=$CLE" \
    -o tordns-maj ./noeud/maj
```

Sur un nœud, `noeud/installer.sh --cle-maj <hex>` transmet la clé à la
construction de `tordns-maj`.

## 2. Publier une version

```bash
./tordns-signer manifeste \
    --dossier ~/tordns-cles \
    --version 2 \
    --expire 2027-01-31T00:00:00Z \
    --cible client-linux-amd64=./dist/tordns-client,https://<adresse>.onion/maj/tordns-client \
    --cible noeud=./dist/tordns-noeud.tar.gz,https://<adresse>.onion/maj/tordns-noeud.tar.gz \
    --image unbound=ghcr.io/tordns/unbound@sha256:<64 hex> \
    --image passerelle=ghcr.io/tordns/passerelle@sha256:<64 hex> \
    --image etat=ghcr.io/tordns/etat@sha256:<64 hex> \
    --adresse coeur=<adresse maîtresse>.onion \
    --sortie ./publication
```

`--cible` calcule la taille et le SHA-256 du fichier local : le manifeste ne
peut pas décrire autre chose que ce qui a été signé. `--image` exige
`nom@sha256:…` ; une étiquette (`:latest`) est refusée, car le registre
pourrait la réécrire.

Le résultat est `publication/manifeste.json` et `manifeste.json.sig`
(64 octets bruts). Les deux fichiers, plus les fichiers des cibles, vont dans
`/var/lib/tordns/maj/` sur **chaque** nœud ; Caddy les sert sous `/maj/`.
Le manifeste et sa signature sont à la racine du miroir. GitHub Releases peut
servir de secours avec les mêmes fichiers.

## 3. Vérifier hors ligne

```bash
./tordns-signer verifier --manifeste ./publication/manifeste.json \
    --signature ./publication/manifeste.json.sig --version-installee 1
```

Sortie non nulle et raison explicite si la signature, l'expiration, la taille,
le SHA-256, une image par étiquette, ou la version (rejeu) sont mauvais.

## 4. Rotation de la clé

1. Créer une nouvelle paire **avant** d'en avoir besoin :
   `./tordns-signer cle --dossier ~/tordns-cles-2`.
2. Publier un manifeste signé par l'**ancienne** clé qui annonce la nouvelle :
   `--cle-suivante <clé publique 2>`.
3. Les nœuds et clients enregistrent cette clé dans leur état après une mise à
   jour réussie ; le manifeste suivant peut être signé par la nouvelle clé.
4. Reconstruire les programmes avec la nouvelle clé épinglée
   (`-ldflags -X tordns/manifeste.ClePubliqueEpinglee=…`) et redistribuer cette
   version.

Conserver l'ancienne clé privée tant que des appareils peuvent encore
l'accepter ; la détruire est une décision explicite. Une clé compromise ne se
« révoque » pas : il faut publier une version signée par l'ancienne clé qui
annonce la nouvelle, puis considérer l'ancienne adresse comme suspecte.
