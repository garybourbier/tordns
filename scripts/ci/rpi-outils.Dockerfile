# TorDNS — outils de l'image Raspberry Pi (Mission 24).
#
# Conteneur non privilégié : mtools et debugfs écrivent dans des fichiers de
# partitions sans montage, QEMU sert à démarrer l'image. Rien n'est monté depuis
# l'hôte, aucun périphérique n'est passé, le conteneur tourne avec l'uid de
# l'utilisateur (images et fichiers restent à lui).
FROM alpine:3.22

RUN apk add --no-cache \
	mtools e2fsprogs e2fsprogs-extra dosfstools coreutils \
	xz python3 qemu-system-aarch64 qemu-img nftables

WORKDIR /w
