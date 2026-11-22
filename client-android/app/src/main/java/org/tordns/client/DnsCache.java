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

    /** TTL minimal de la section réponse, borné par la durée maximale. */
    static long ttlMs(byte[] reponse, long dureeMaxMs) {
        long min = Long.MAX_VALUE;
        try {
            int p = DnsMessage.finQuestion(reponse);
            int an = DnsMessage.nombreReponses(reponse);
            for (int i = 0; i < an; i++) {
                p += DnsMessage.longueurNom(reponse, p);
                if (p + 10 > reponse.length) {
                    return 0;
                }
                long ttl = ((long) (reponse[p + 4] & 0xff) << 24)
                        | ((long) (reponse[p + 5] & 0xff) << 16)
                        | ((long) (reponse[p + 6] & 0xff) << 8)
                        | (reponse[p + 7] & 0xff);
                min = Math.min(min, ttl);
                int rdlen = ((reponse[p + 8] & 0xff) << 8) | (reponse[p + 9] & 0xff);
                p += 10 + rdlen;
            }
        } catch (RuntimeException e) {
            return 0;
        }
        if (min == Long.MAX_VALUE) {
            return 0;
        }
        return Math.min(dureeMaxMs, min * 1000L);
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
