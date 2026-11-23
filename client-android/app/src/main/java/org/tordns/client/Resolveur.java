package org.tordns.client;

import android.content.Context;

import java.io.File;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Cœur partagé entre l'interface et le service VPN : un seul bootstrap Tor,
 * un cache mémoire, et des appels DoH sérialisés par un pool borné.
 */
final class Resolveur {
    interface Ecouteur {
        void surEtat(String message);
    }

    static final Resolveur INSTANCE = new Resolveur();

    private final ExecutorService pool = Executors.newFixedThreadPool(16);
    private final DnsCache cache = new DnsCache(512, 3600_000L);
    private final AtomicBoolean demarrage = new AtomicBoolean(false);
    private final AtomicLong total = new AtomicLong();
    private final AtomicLong hits = new AtomicLong();
    private final AtomicLong erreurs = new AtomicLong();
    private volatile boolean pret = false;
    private volatile String etat = "Tor arrêté";
    private volatile String onion = "";
    private volatile boolean dnssec = true;

    private Resolveur() {}

    String onion() {
        return onion;
    }

    void configurer(String adresse) {
        onion = adresse == null ? "" : adresse.trim().toLowerCase(java.util.Locale.ROOT);
    }

    void setDnssec(boolean actif) {
        dnssec = actif;
    }

    boolean pret() {
        return pret;
    }

    String etat() {
        return etat;
    }

    long total() {
        return total.get();
    }

    long hits() {
        return hits.get();
    }

    long erreurs() {
        return erreurs.get();
    }

    int tailleCache() {
        return cache.taille();
    }

    /** Démarre Tor une seule fois ; l'appel est bloquant, à lancer hors du fil UI. */
    synchronized void demarrer(Context contexte, Ecouteur ecouteur) {
        if (pret) {
            if (ecouteur != null) {
                ecouteur.surEtat(etat);
            }
            return;
        }
        if (!demarrage.compareAndSet(false, true)) {
            return;
        }
        if (onion.isEmpty()) {
            demarrage.set(false);
            etat = "Adresse .onion manquante";
            if (ecouteur != null) {
                ecouteur.surEtat(etat);
            }
            return;
        }
        etat = "Bootstrap Tor…";
        if (ecouteur != null) {
            ecouteur.surEtat(etat);
        }
        Thread fil = new Thread(() -> {
            android.util.Log.i("TorDNS", "bootstrap : appel Arti");
            File etatDir = new File(contexte.getFilesDir(), "arti-etat");
            File cacheDir = new File(contexte.getCacheDir(), "arti-cache");
            etatDir.mkdirs();
            cacheDir.mkdirs();
            String erreur = Arti.demarrer(etatDir.getAbsolutePath(), cacheDir.getAbsolutePath());
            android.util.Log.i("TorDNS", "bootstrap : retour " + (erreur == null ? "OK" : erreur));
            if (erreur == null) {
                pret = true;
                etat = "Tor prêt";
            } else {
                etat = erreur;
            }
            demarrage.set(false);
            if (ecouteur != null) {
                ecouteur.surEtat(etat);
            }
        }, "arti-bootstrap");
        fil.setDaemon(true);
        fil.start();
    }

    void arreter() {
        pret = false;
        etat = "Tor arrêté";
        Arti.arreter();
    }

    /** Bloquant : renvoie la réponse DNS, ou SERVFAIL si le relais échoue. */
    byte[] resoudre(byte[] requete) {
        total.incrementAndGet();
        try {
            String cle = DnsMessage.cle(requete);
            int id = DnsMessage.id(requete);
            byte[] enCache = cache.obtenir(cle, id);
            if (enCache != null) {
                hits.incrementAndGet();
                return enCache;
            }
            if (!pret) {
                erreurs.incrementAndGet();
                return DnsMessage.servfail(requete);
            }
            byte[] reponse;
            if (dnssec) {
                try {
                    reponse = Dnssec.valider(onion, requete);
                } catch (java.io.IOException e) {
                    // Signature fausse ou chaîne rompue : on ne renvoie surtout
                    // pas la réponse du nœud, même si elle semble bien formée.
                    erreurs.incrementAndGet();
                    return DnsMessage.servfail(requete);
                }
            } else {
                reponse = Arti.doh(onion, requete, 20000);
            }
            if (reponse == null || reponse.length < 12 || (reponse[2] & 0x80) == 0) {
                erreurs.incrementAndGet();
                return DnsMessage.servfail(requete);
            }
            cache.poser(cle, reponse);
            return DnsMessage.avecId(reponse, id);
        } catch (RuntimeException e) {
            erreurs.incrementAndGet();
            return DnsMessage.servfail(requete);
        }
    }

    ExecutorService pool() {
        return pool;
    }

    void viderCache() {
        cache.vider();
    }
}
