#!/usr/bin/env python3
"""Test système OpenWrt dans QEMU (mission 23).

L'image OpenWrt x86_64 officielle démarre dans QEMU **à l'intérieur d'un
conteneur Docker non privilégié** : ni `--privileged`, ni `--device`, ni montage
de `/dev`, ni `--network host`. QEMU ne voit donc aucun périphérique de la
machine hôte ; le chien de garde matériel qui avait redémarré le PC le 24/11
n'est pas atteignable. Voir docs/missions/23-openwrt.md, section INTERDIT.

Le script invité client-openwrt/testdata/qemu-test.sh est récupéré par HTTP
depuis le conteneur (10.0.2.2) et son verdict est lu sur le port série.
"""
import argparse
import os
import socket
import subprocess
import sys
import threading
import time

NOM = "tordns-openwrt-qemu"
IMAGE = "tordns-qemu-openwrt"
DOCKERFILE = """FROM alpine:3.22
RUN apk add --no-cache qemu-system-x86_64 busybox-extras
ENTRYPOINT ["qemu-system-x86_64"]
"""


class Console:
    """Console série drainée en permanence : sans lecture continue, le tampon
    du terminal saturé bloque l'invité."""

    def __init__(self, sock):
        self.sock = sock
        self.buf = bytearray()
        self.verrou = threading.Lock()
        self.actif = True
        self.fil = threading.Thread(target=self._lire, daemon=True)
        self.fil.start()

    def _lire(self):
        self.sock.settimeout(0.5)
        while self.actif:
            try:
                d = self.sock.recv(65536)
            except socket.timeout:
                continue
            except OSError:
                break
            if not d:
                break
            with self.verrou:
                self.buf += d

    def vider(self):
        with self.verrou:
            self.buf.clear()

    def texte(self):
        with self.verrou:
            return bytes(self.buf)

    def ecrire(self, data):
        self.sock.sendall(data)

    def ligne(self, cmd, pause=0.3):
        self.sock.sendall((cmd + "\n").encode())
        time.sleep(pause)


def docker(*args, **kwargs):
    return subprocess.run(["docker", *args], **kwargs)


def nettoyer():
    docker("rm", "-f", NOM, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def preparer_image():
    """Construit l'image du conteneur QEMU si elle n'existe pas."""
    r = docker("image", "inspect", IMAGE, stdout=subprocess.DEVNULL,
               stderr=subprocess.DEVNULL)
    if r.returncode == 0:
        return
    print("construction du conteneur QEMU (alpine + qemu-system-x86_64)…")
    r = subprocess.run(["docker", "build", "-q", "-t", IMAGE, "-"],
                       input=DOCKERFILE.encode(), stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT)
    if r.returncode != 0:
        sys.stdout.write(r.stdout.decode("utf-8", "replace"))
        raise SystemExit("construction du conteneur QEMU impossible")


def demarrer(run):
    nettoyer()
    sock_path = os.path.join(run, "serial.sock")
    if os.path.exists(sock_path):
        os.unlink(sock_path)
    cmd = [
        "docker", "run", "--rm", "--name", NOM,
        "-v", run + ":/data",
        "--user", "%d:%d" % (os.getuid(), os.getgid()),
        "--entrypoint", "sh", IMAGE, "-c",
        "cd /data/files && httpd -p 8123 -h /data/files; "
        "exec qemu-system-x86_64 -m 256 -smp 2 -display none "
        "-drive file=/data/openwrt.img,format=raw,snapshot=on "
        "-nic user,model=e1000 -nic user,model=e1000 "
        "-chardev socket,id=ser0,path=/data/serial.sock,server=on,wait=off "
        "-serial chardev:ser0",
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                            stderr=subprocess.STDOUT)
    for _ in range(150):
        if os.path.exists(sock_path):
            break
        time.sleep(0.2)
    else:
        raise SystemExit("socket série QEMU absent")
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(sock_path)
    return proc, Console(sock)


def attendre(console, motif, delai=120, entree=True):
    if isinstance(motif, str):
        motif = motif.encode()
    debut = time.time()
    dernier = 0.0
    vu = 0
    verbeux = os.environ.get("TORDNS_QEMU_VERBEUX") == "1"
    while time.time() - debut < delai:
        if motif in console.texte():
            return True
        if verbeux:
            maintenant = console.texte()
            if len(maintenant) > vu:
                sys.stdout.write(maintenant[vu:].decode("utf-8", "replace"))
                sys.stdout.flush()
                vu = len(maintenant)
        if entree and time.time() - dernier > 5:
            console.ecrire(b"\n")
            dernier = time.time()
        time.sleep(0.3)
    return False


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--run", default="/tmp/tordns-openwrt-qemu")
    p.add_argument("--script", default="qemu-test.sh")
    p.add_argument("--attente", type=int, default=420)
    a = p.parse_args()
    if not os.path.exists(os.path.join(a.run, "openwrt.img")):
        raise SystemExit("image OpenWrt absente : %s/openwrt.img" % a.run)
    preparer_image()
    proc, console = demarrer(a.run)
    try:
        if not attendre(console, b"root@OpenWrt", 360):
            raise SystemExit("console OpenWrt absente")
        time.sleep(8)
        console.vider()
        console.ligne("echo PRET", 0.5)
        if not attendre(console, "PRET", 60, entree=False):
            raise SystemExit("console muette")
        console.vider()
        # Sans WAN configuré, l'invité ne peut pas récupérer le script par HTTP
        # (la carte eth1 n'a pas encore de bail). On configure le WAN ici, comme
        # le ferait l'utilisateur sur un routeur, avant l'envoi.
        for cmd in (
            "uci set network.wan=interface",
            "uci set network.wan.device='eth1'",
            "uci set network.wan.proto='dhcp'",
            "uci commit network",
            "/etc/init.d/network reload >/dev/null 2>&1",
            "i=0; while ! ip addr show eth1 | grep -q 'inet ' && "
            "[ $i -lt 30 ]; do sleep 1; i=$((i+1)); done; echo WAN-PRET",
        ):
            console.ligne(cmd, 0.4)
        if not attendre(console, "WAN-PRET", 90, entree=False):
            raise SystemExit("WAN du routeur QEMU non configuré")
        console.vider()
        commande = ("wget -q -O /tmp/%s http://10.0.2.2:8123/%s && "
                    "sh /tmp/%s" % (a.script, a.script, a.script))
        console.ligne(commande, 0.5)
        if not attendre(console, "FIN-TEST", a.attente, entree=False):
            raise SystemExit("test invité sans fin")
        console.vider()
        console.ligne("cat /tmp/resultat.log; echo VERDICT=$?", 1.0)
        if not attendre(console, "VERDICT=", 120, entree=False):
            raise SystemExit("verdict illisible")
        brut = console.texte().decode("utf-8", "replace")
    finally:
        console.actif = False
        nettoyer()
        proc.wait(timeout=30)

    # N'affiche que le journal du test, sans le bruit de la console.
    debut = brut.find("== WAN ==")
    fin = brut.rfind("code=")
    if debut == -1 or fin == -1:
        sys.stdout.write(brut)
        raise SystemExit("verdict du test système illisible")
    print(brut[debut:fin + len("code=0")])
    if "code=1" in brut[fin:fin + 20]:
        raise SystemExit("test système OpenWrt en échec")
    print("code=0")


if __name__ == "__main__":
    main()
