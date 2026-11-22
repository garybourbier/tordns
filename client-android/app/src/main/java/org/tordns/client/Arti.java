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

    static native String derniereErreur();

    static native void arreter();
}
