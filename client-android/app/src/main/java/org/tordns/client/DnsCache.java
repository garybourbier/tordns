package org.tordns.client;

import java.util.LinkedHashMap;
import java.util.Map;

/** Cache LRU des réponses DNS, valable uniquement en mémoire. */
final class DnsCache {
    static final class Entree {
        final byte[] reponse;
        final long expire;
        final long pose;

        Entree(byte[] reponse, long expire, long pose) {
            this.reponse = reponse;
            this.expire = expire;
            this.pose = pose;
        }
    }

    private final int tailleMax;
    private final long dureeMaxMs;
    private final LinkedHashMap<String, Entree> entrees;

    DnsCache(int tailleMax, long dureeMaxMs) {
        this.tailleMax = Math.max(1, tailleMax);
        this.dureeMaxMs = Math.max(1000, dureeMaxMs);
        this.entrees = new LinkedHashMap<String, Entree>(64, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<String, Entree> eldest) {
                return size() > DnsCache.this.tailleMax;
            }
        };
    }

    /**
     * TTL de la section réponse, ou TTL négatif du SOA (RFC 2308) pour
     * NXDOMAIN/NODATA. TTL nul : pas de cache ; plafond fourni.
     */
    static long ttlMs(byte[] reponse, long dureeMaxMs) {
        long min = Long.MAX_VALUE;
        try {
            int p = DnsMessage.finQuestion(reponse);
            int an = DnsMessage.nombreReponses(reponse);
            for (int i = 0; i < an; i++) {
                int[] rr = lireRR(reponse, p);
                min = Math.min(min, rr[1]);
                p = rr[3];
            }
            if (DnsMessage.rcode(reponse) == 0 && an > 0) {
                return borne(min, dureeMaxMs);
            }
            // Réponse négative : le SOA de l'autorité porte le TTL.
            int ns = DnsMessage.nombreAutorites(reponse);
            for (int i = 0; i < ns; i++) {
                int[] rr = lireRR(reponse, p);
                if (rr[0] == 6 && rr[3] - rr[2] >= 4) {
                    long minimum = entier32(reponse, rr[3] - 4);
                    min = Math.min(min, Math.min(rr[1], minimum));
                }
                p = rr[3];
            }
        } catch (RuntimeException e) {
            return 0;
        }
        return min == Long.MAX_VALUE ? 0 : borne(min, dureeMaxMs);
    }

    private static long borne(long ttl, long dureeMaxMs) {
        if (ttl == 0) {
            return 0;
        }
        return Math.min(Math.max(1000L, dureeMaxMs), ttl * 1000L);
    }

    /** Renvoie type, TTL, début des données et position suivante. */
    private static int[] lireRR(byte[] m, int p) {
        p += DnsMessage.longueurNom(m, p);
        if (p + 10 > m.length) {
            throw new IllegalArgumentException("RR tronqué");
        }
        int type = ((m[p] & 0xff) << 8) | (m[p + 1] & 0xff);
        int ttl = (int) entier32(m, p + 4);
        int rdlen = ((m[p + 8] & 0xff) << 8) | (m[p + 9] & 0xff);
        int debut = p + 10;
        int fin = debut + rdlen;
        if (fin > m.length) {
            throw new IllegalArgumentException("données tronquées");
        }
        return new int[] {type, ttl, debut, fin};
    }

    private static long entier32(byte[] m, int p) {
        return ((long) (m[p] & 0xff) << 24)
                | ((long) (m[p + 1] & 0xff) << 16)
                | ((long) (m[p + 2] & 0xff) << 8)
                | (m[p + 3] & 0xff);
    }

    synchronized byte[] obtenir(String cle, int id) {
        Entree e = entrees.get(cle);
        if (e == null) {
            return null;
        }
        long maintenant = System.currentTimeMillis();
        if (maintenant >= e.expire) {
            entrees.remove(cle);
            return null;
        }
        byte[] copie = e.reponse.clone();
        DnsMessage.ajusterTtl(copie, (maintenant - e.pose) / 1000L);
        return DnsMessage.avecId(copie, id);
    }

    synchronized void poser(String cle, byte[] reponse) {
        if (!DnsMessage.cacheable(reponse)) {
            return;
        }
        long duree = ttlMs(reponse, dureeMaxMs);
        if (duree <= 0) {
            return;
        }
        long maintenant = System.currentTimeMillis();
        entrees.put(cle, new Entree(reponse.clone(), maintenant + duree, maintenant));
    }

    synchronized void vider() {
        entrees.clear();
    }

    synchronized int taille() {
        return entrees.size();
    }
}
