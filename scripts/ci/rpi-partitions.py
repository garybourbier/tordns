#!/usr/bin/env python3
"""TorDNS — partitions d'une image disque, sans montage ni privilèges (Mission 24).

L'image Raspberry Pi OS contient une table MBR : une partition FAT de démarrage
et une partition ext4 racine. Pour les modifier sans root, on les extrait dans
deux fichiers, on les édite (mtools, debugfs) puis on les réinsère.

Sous-commandes :

    extraire <image> <boot.fat> <racine.ext4>
    assembler <image> <boot.fat> <racine.ext4> <sortie>
    arrondir <sortie>          étend le fichier à la puissance de 2 supérieure
"""

import os
import struct
import sys


def partitions(image):
    with open(image, "rb") as f:
        mbr = f.read(512)
    if mbr[510:512] != b"\x55\xaa":
        raise SystemExit("table de partitions absente (pas un MBR)")
    trouvees = []
    for i in range(4):
        entree = mbr[446 + 16 * i: 446 + 16 * (i + 1)]
        type_part, = struct.unpack_from("<B", entree, 4)
        debut, = struct.unpack_from("<I", entree, 8)
        taille, = struct.unpack_from("<I", entree, 12)
        if type_part == 0 or taille == 0:
            continue
        trouvees.append((type_part, debut * 512, taille * 512))
    if len(trouvees) != 2:
        raise SystemExit(f"deux partitions attendues, {len(trouvees)} trouvées")
    return trouvees


def extraire(image, boot, racine):
    (_, o1, t1), (_, o2, t2) = partitions(image)
    with open(image, "rb") as src:
        for offset, taille, chemin in ((o1, t1, boot), (o2, t2, racine)):
            src.seek(offset)
            reste = taille
            with open(chemin, "wb") as dst:
                while reste:
                    bloc = src.read(min(4 << 20, reste))
                    if not bloc:
                        raise SystemExit(f"lecture interrompue dans {image}")
                    dst.write(bloc)
                    reste -= len(bloc)


def assembler(image, boot, racine, sortie):
    (_, o1, t1), (_, o2, t2) = partitions(image)
    tailles = []
    for chemin, ancienne in ((boot, t1), (racine, t2)):
        taille = os.path.getsize(chemin)
        if taille < ancienne:
            raise SystemExit(f"{chemin} fait {taille} octets, au moins {ancienne} attendus")
        if taille % 512:
            raise SystemExit(f"{chemin} n'est pas un multiple de 512 octets")
        tailles.append(taille)

    with open(image, "rb") as src, open(sortie, "wb") as dst:
        entete = bytearray(src.read(o1))
        # La partition racine peut avoir été agrandie : la table MBR doit dire
        # la vérité, sinon le noyau lit une partition plus petite que le fs.
        for i, taille in enumerate(tailles):
            struct.pack_into("<I", entete, 446 + 16 * i + 12, taille // 512)
        dst.write(entete)
        for chemin, taille, offset in ((boot, tailles[0], o1), (racine, tailles[1], o2)):
            dst.seek(offset)
            with open(chemin, "rb") as part:
                reste = taille
                while reste:
                    bloc = part.read(min(4 << 20, reste))
                    if not bloc:
                        raise SystemExit(f"lecture interrompue dans {chemin}")
                    dst.write(bloc)
                    reste -= len(bloc)
        dst.truncate(o2 + tailles[1])


def arrondir(chemin):
    """QEMU exige une carte SD d'une puissance de 2 en octets : 4 Gio ici.

    Le surplus reste non alloué ; le premier démarrage étend la partition.
    """
    taille = os.path.getsize(chemin)
    cible = 1 << (taille - 1).bit_length()
    if cible == taille:
        return
    with open(chemin, "r+b") as f:
        f.truncate(cible)
    print(f"image étendue à {cible // (1 << 30)} Gio")


def main(argv):
    if len(argv) < 2:
        raise SystemExit(__doc__)
    commande, *reste = argv[1:]
    if commande == "extraire" and len(reste) == 3:
        extraire(*reste)
    elif commande == "assembler" and len(reste) == 4:
        assembler(*reste)
    elif commande == "arrondir" and len(reste) == 1:
        arrondir(*reste)
    else:
        raise SystemExit(__doc__)


if __name__ == "__main__":
    main(sys.argv)
