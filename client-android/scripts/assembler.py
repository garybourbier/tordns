#!/usr/bin/env python3
"""Ajoute classes.dex et les .so à l'APK produit par aapt2.

Les bibliothèques natives sont stockées sans compression (exigence de
l'extraction directe) ; zipalign les aligne ensuite sur 4 octets.
usage : assembler.py base.apk dossier_ajouts sortie.apk
"""

import sys
import zipfile
from pathlib import Path


def main() -> int:
    base, ajouts, sortie = (Path(a) for a in sys.argv[1:4])
    with zipfile.ZipFile(base) as source, zipfile.ZipFile(sortie, "w") as cible:
        for info in source.infolist():
            cible.writestr(info, source.read(info.filename))

        for fichier in sorted(ajouts.rglob("*")):
            if not fichier.is_file():
                continue
            nom = fichier.relative_to(ajouts).as_posix()
            methode = (
                zipfile.ZIP_STORED
                if nom.startswith("lib/") or nom.endswith(".dex")
                else zipfile.ZIP_DEFLATED
            )
            cible.write(fichier, nom, compress_type=methode)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
