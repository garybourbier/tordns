#!/usr/bin/env python3
"""Capture et mesure une page locale via le protocole DevTools de Chromium.

Chromium headless impose une largeur de fenêtre minimale de 500 px ; ce script
utilise Emulation.setDeviceMetricsOverride pour tester réellement 360 px.
Aucun accès réseau hors la boucle locale de débogage.
"""
import argparse
import base64
import json
import pathlib
import socket
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request

import websocket


def port_libre():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def attendre(url, secondes=15):
    fin = time.time() + secondes
    while time.time() < fin:
        try:
            with urllib.request.urlopen(url, timeout=1) as r:
                return json.load(r)
        except Exception:
            time.sleep(0.1)
    raise RuntimeError(f"Chromium ne répond pas : {url}")


class Cdp:
    def __init__(self, ws):
        self.ws = ws
        self.id = 0

    def envoyer(self, methode, params=None):
        self.id += 1
        self.ws.send(json.dumps({"id": self.id, "method": methode, "params": params or {}}))
        while True:
            message = json.loads(self.ws.recv())
            if message.get("id") == self.id:
                if "error" in message:
                    raise RuntimeError(message["error"])
                return message.get("result", {})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("page")
    parser.add_argument("largeur", type=int)
    parser.add_argument("capture")
    parser.add_argument("--chromium", default="chromium")
    args = parser.parse_args()

    port = port_libre()
    profil = tempfile.mkdtemp(prefix="tordns-chromium-")
    processus = subprocess.Popen(
        [args.chromium, "--headless", "--no-sandbox", "--disable-gpu",
         "--hide-scrollbars", "--remote-allow-origins=*",
         f"--remote-debugging-port={port}",
         f"--user-data-dir={profil}", "about:blank"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        attendre(f"http://127.0.0.1:{port}/json/version")
        url = pathlib.Path(args.page).resolve().as_uri()
        requete = urllib.request.Request(
            f"http://127.0.0.1:{port}/json/new?{urllib.parse.quote(url, safe='')}",
            method="PUT",
        )
        with urllib.request.urlopen(requete, timeout=5) as r:
            cible = json.load(r)
        ws = websocket.create_connection(cible["webSocketDebuggerUrl"], timeout=10)
        cdp = Cdp(ws)
        cdp.envoyer("Page.enable")
        cdp.envoyer("Emulation.setDeviceMetricsOverride", {
            "width": args.largeur, "height": 1200, "deviceScaleFactor": 1,
            "mobile": False,
        })
        cdp.envoyer("Page.navigate", {"url": url})
        fin = time.time() + 15
        while time.time() < fin:
            etat = cdp.envoyer("Runtime.evaluate", {
                "expression": "document.readyState", "returnByValue": True,
            })
            if etat.get("result", {}).get("value") == "complete":
                break
            time.sleep(0.1)
        time.sleep(0.8)
        mesures = cdp.envoyer("Runtime.evaluate", {
            "expression": "({l: document.documentElement.scrollWidth, h: document.documentElement.scrollHeight})",
            "returnByValue": True,
        })["result"]["value"]
        hauteur = min(max(1200, mesures["h"]), 8000)
        image = cdp.envoyer("Page.captureScreenshot", {
            "format": "png", "fromSurface": True, "captureBeyondViewport": True,
            "clip": {"x": 0, "y": 0, "width": args.largeur, "height": hauteur, "scale": 1},
        })
        pathlib.Path(args.capture).parent.mkdir(parents=True, exist_ok=True)
        pathlib.Path(args.capture).write_bytes(base64.b64decode(image["data"]))
        print(json.dumps({"largeur": args.largeur, "scrollWidth": mesures["l"],
                          "hauteur": hauteur, "capture": args.capture}))
        ws.close()
    finally:
        processus.terminate()
        try:
            processus.wait(timeout=5)
        except subprocess.TimeoutExpired:
            processus.kill()


if __name__ == "__main__":
    main()
