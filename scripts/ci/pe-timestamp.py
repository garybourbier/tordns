#!/usr/bin/env python3
"""Fixe l'horodatage PE (IMAGE_FILE_HEADER.TimeDateStamp) à SOURCE_DATE_EPOCH.

Les linkers PE écrivent sinon l'heure de compilation, ce qui rend deux builds
identiques binairement différents. Ne touche ni au checksum ni aux autres
champs. usage : pe-timestamp.py fichier.exe <epoch>
"""
import struct
import sys


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit("usage : pe-timestamp.py fichier.exe <epoch>")
    chemin = sys.argv[1]
    epoch = int(sys.argv[2], 0)
    if epoch < 0 or epoch > 0xFFFFFFFF:
        raise SystemExit("epoch hors plage PE")
    with open(chemin, "r+b") as f:
        f.seek(0)
        if f.read(2) != b"MZ":
            raise SystemExit(f"{chemin} : signature MZ absente")
        f.seek(0x3C)
        (offset,) = struct.unpack("<I", f.read(4))
        if offset < 0x40 or offset > 0x10000000:
            raise SystemExit(f"{chemin} : e_lfanew invalide")
        f.seek(offset)
        if f.read(4) != b"PE\0\0":
            raise SystemExit(f"{chemin} : signature PE absente")
        f.seek(offset + 8)
        f.write(struct.pack("<I", epoch))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
