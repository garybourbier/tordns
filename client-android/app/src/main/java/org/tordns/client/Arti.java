package org.tordns.client;

/** Pont vers la bibliothèque Tor (Arti) compilée en Rust. */
final class Arti {
    static {
        System.loadLibrary("tordns_arti");
    }

    private Arti() {}

    /** Bloquant (30 à 120 s) : démarre Tor. Renvoie null en cas de succès. */
    static native String demarrer(String repertoireEtat, String repertoireCache);

    /** Bloquant : POST DoH vers {@code onion}. Renvoie null en cas d'échec. */
    static native byte[] doh(String onion, byte[] requete, int delaiMs);

    /** Vérifie un manifeste signé. Renvoie la cible Android ou null. */
    static native String verifierManifeste(byte[] manifeste, byte[] signature,
            long versionInstallee, long maintenant);

    /** Télécharge un chemin du miroir par Tor (HTTP GET borné). */
    static native byte[] telecharger(String onion, String chemin, int max);

    static native String derniereErreur();

    static native void arreter();
}
