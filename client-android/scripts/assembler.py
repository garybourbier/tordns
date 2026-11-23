#!/usr/bin/env python3
"""Ajoute classes.dex et les .so à l'APK produit par aapt2.

Les entrées sont triées par nom et horodatées avec SOURCE_DATE_EPOCH : deux
constructions à partir du même code produisent le même APK non signé.
Les bibliothèques natives restent non compressées ; zipalign les aligne
ensuite sur 4 octets (16 Kio pour les pages Android 16).
usage : assembler.py base.apk dossier_ajouts sortie.apk
"""

import os
import sys
import time
import zipfile
from pathlib import Path

DATE_MIN = (1980, 1, 1, 0, 0, 0)


def date_fixe() -> tuple:
    try:
        epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))
    except ValueError:
        epoch = 0
    if epoch <= 0:
        return DATE_MIN
    t = time.gmtime(epoch)
    if t.tm_year < 1980:
        return DATE_MIN
    return (t.tm_year, t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec)


def main() -> int:
    if len(sys.argv) != 4:
        raise SystemExit("usage : assembler.py base.apk dossier_ajouts sortie.apk")
    base, ajouts, sortie = (Path(a) for a in sys.argv[1:4])
    date = date_fixe()
    entrees = []

    with zipfile.ZipFile(base) as source:
        for info in source.infolist():
            if info.is_dir():
                continue
            entrees.append((info.filename, source.read(info.filename),
                            info.compress_type, info.external_attr))

    for fichier in sorted(ajouts.rglob("*")):
        if not fichier.is_file():
            continue
        nom = fichier.relative_to(ajouts).as_posix()
        methode = (
            zipfile.ZIP_STORED
            if nom.startswith("lib/") or nom.endswith(".dex")
            else zipfile.ZIP_DEFLATED
        )
        entrees.append((nom, fichier.read_bytes(), methode, 0o100644 << 16))

    entrees.sort(key=lambda e: e[0])
    with zipfile.ZipFile(sortie, "w", compression=zipfile.ZIP_DEFLATED,
                         compresslevel=9) as cible:
        for nom, données, methode, attributs in entrees:
            info = zipfile.ZipInfo(nom, date_time=date)
            info.compress_type = methode
            info.create_system = 3
            info.external_attr = attributs
            cible.writestr(info, données)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
