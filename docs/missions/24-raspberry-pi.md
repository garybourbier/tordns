# Mission 24 — Nœud prêt pour Raspberry Pi

But : un bénévole flashe une carte SD, branche son Raspberry Pi, et devient un nœud
communauté sans connaître Docker.

## À livrer

- `noeud/raspberry/` : image à flasher construite par `scripts/ci/image-rpi.sh` à partir de
  **Raspberry Pi OS Lite 64 bits** officiel (téléchargé, SHA-256 épinglé), modifiée hors
  ligne (montage en boucle + `systemd-nspawn` ou `qemu-user-static`) : Docker installé, nœud
  TorDNS pré-installé par `installer.sh` en mode images GHCR par empreinte, mises à jour
  signées actives, SSH **désactivé** par défaut, aucun mot de passe par défaut connu.
- Premier démarrage (`tordns-premier-demarrage.service`) : génère les clés `.onion` sur la
  carte (jamais dans l'image), étend la partition, active le pare-feu, puis lance
  l'inscription au registre communauté si le fichier `tordns.txt` de la partition de boot
  le demande (adresse du registre et contact facultatif écrits par le bénévole avant de
  brancher).
- Page d'état locale sur le LAN (`http://tordns.local`, mDNS) : nœud en ligne, adresse
  d'instance, inscription en quarantaine/admis, mises à jour ; aucune requête DNS affichée.
- Matériel cible et minimum documentés (Pi 4 2 Go, Pi 5 ; Pi 3 avec réserve à mesurer),
  carte SD vs SSD, consommation.
- Image compressée `.img.xz` + SHA-256 ajoutée à la release (pas plus de 2 Go).

## Preuve (`scripts/verifier-m24.sh`)

Image construite ; elle démarre dans QEMU `raspi3b` ou `virt` aarch64 avec le noyau de
l'image (ou à défaut le rootfs dans `systemd-nspawn`) jusqu'au service de premier
démarrage, qui crée des clés différentes à chaque démarrage d'une copie neuve ; aucune clé
ni mot de passe dans l'image (recherche dans le rootfs). NON PROUVÉ attendu : vrai Pi.
