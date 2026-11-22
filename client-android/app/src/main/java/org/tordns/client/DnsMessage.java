package org.tordns.client;

import java.nio.charset.StandardCharsets;

/** Petites opérations sur le format DNS wire (RFC 1035). */
final class DnsMessage {
    private DnsMessage() {}

    /** Longueur d'un nom à partir de {@code offset}, pointeurs de compression compris. */
    static int longueurNom(byte[] m, int offset) {
        int i = offset;
        while (i < m.length) {
            int l = m[i] & 0xff;
            if (l == 0) {
                return i - offset + 1;
            }
            if ((l & 0xc0) == 0xc0) {
                return i - offset + 2;
            }
            if ((l & 0xc0) != 0) {
                throw new IllegalArgumentException("label invalide");
            }
            i += l + 1;
        }
        throw new IllegalArgumentException("nom tronqué");
    }

    /** Position juste après la question (nom + type + classe). */
    static int finQuestion(byte[] m) {
        if (m.length < 12) {
            throw new IllegalArgumentException("en-tête tronqué");
        }
        int qd = ((m[4] & 0xff) << 8) | (m[5] & 0xff);
        if (qd != 1) {
            throw new IllegalArgumentException("une seule question attendue");
        }
        int p = 12 + longueurNom(m, 12);
        if (p + 4 > m.length) {
            throw new IllegalArgumentException("question tronquée");
        }
        return p + 4;
    }

    static String nom(byte[] m, int offset) {
        StringBuilder sb = new StringBuilder();
        int i = offset;
        int sauts = 0;
        while (i < m.length) {
            int l = m[i] & 0xff;
            if (l == 0) {
                break;
            }
            if ((l & 0xc0) == 0xc0) {
                if (++sauts > 16 || i + 1 >= m.length) {
                    throw new IllegalArgumentException("compression invalide");
                }
                i = ((l & 0x3f) << 8) | (m[i + 1] & 0xff);
                continue;
            }
            if ((l & 0xc0) != 0 || i + 1 + l > m.length) {
                throw new IllegalArgumentException("label invalide");
            }
            if (sb.length() > 0) {
                sb.append('.');
            }
            sb.append(new String(m, i + 1, l, StandardCharsets.ISO_8859_1));
            i += l + 1;
        }
        return sb.toString().toLowerCase(java.util.Locale.ROOT);
    }

    static int type(byte[] m, int finQuestion) {
        return ((m[finQuestion - 4] & 0xff) << 8) | (m[finQuestion - 3] & 0xff);
    }

    static int classe(byte[] m, int finQuestion) {
        return ((m[finQuestion - 2] & 0xff) << 8) | (m[finQuestion - 1] & 0xff);
    }

    /** Bit DO de l'OPT, s'il est présent dans la section additionnelle. */
    static boolean demandeDnssec(byte[] m) {
        try {
            int p = finQuestion(m);
            int an = ((m[6] & 0xff) << 8) | (m[7] & 0xff);
            int ns = ((m[8] & 0xff) << 8) | (m[9] & 0xff);
            int ar = ((m[10] & 0xff) << 8) | (m[11] & 0xff);
            p = sauterEnregistrements(m, p, an + ns);
            for (int i = 0; i < ar && p + 10 <= m.length; i++) {
                p += longueurNom(m, p);
                int t = ((m[p] & 0xff) << 8) | (m[p + 1] & 0xff);
                int classe = ((m[p + 2] & 0xff) << 8) | (m[p + 3] & 0xff);
                int rdlen = ((m[p + 8] & 0xff) << 8) | (m[p + 9] & 0xff);
                if (t == 41 && p + 8 <= m.length) {
                    // TTL de l'OPT : 8 bits étendus, 8 bits version, 16 bits drapeaux.
                    // Le bit DO (0x8000) est le bit de poids fort de l'octet p+6.
                    return (m[p + 6] & 0x80) != 0;
                }
                p += 10 + rdlen;
            }
        } catch (RuntimeException ignore) {
            // Une requête illisible n'aura simplement pas la clé DNSSEC.
        }
        return false;
    }

    private static int sauterEnregistrements(byte[] m, int p, int nombre) {
        for (int i = 0; i < nombre; i++) {
            p += longueurNom(m, p);
            if (p + 10 > m.length) {
                throw new IllegalArgumentException("RR tronqué");
            }
            int rdlen = ((m[p + 8] & 0xff) << 8) | (m[p + 9] & 0xff);
            p += 10 + rdlen;
        }
        return p;
    }

    /** Clé de cache : nom normalisé + type + classe + bit DO. */
    static String cle(byte[] m) {
        int fin = finQuestion(m);
        return nom(m, 12) + "|" + type(m, fin) + "|" + classe(m, fin) + "|"
                + (demandeDnssec(m) ? "do" : "plain");
    }

    static int id(byte[] m) {
        return ((m[0] & 0xff) << 8) | (m[1] & 0xff);
    }

    static byte[] avecId(byte[] reponse, int id) {
        byte[] copie = reponse.clone();
        if (copie.length >= 2) {
            copie[0] = (byte) (id >> 8);
            copie[1] = (byte) id;
        }
        return copie;
    }

    static int rcode(byte[] m) {
        return m.length > 3 ? m[3] & 0x0f : -1;
    }

    static boolean tronquee(byte[] m) {
        return m.length > 2 && (m[2] & 0x02) != 0;
    }

    /** NOERROR et NXDOMAIN non tronquées : le TTL décide ensuite. */
    static boolean cacheable(byte[] m) {
        return m.length >= 12 && (rcode(m) == 0 || rcode(m) == 3) && !tronquee(m);
    }

    static int nombreReponses(byte[] m) {
        return m.length >= 8 ? ((m[6] & 0xff) << 8) | (m[7] & 0xff) : 0;
    }

    static int nombreAutorites(byte[] m) {
        return m.length >= 10 ? ((m[8] & 0xff) << 8) | (m[9] & 0xff) : 0;
    }

    /**
     * Décrémente de {@code ecart} secondes chaque TTL de la section réponse,
     * avec un plancher d'une seconde. Les TTL d'origine ne sont jamais dépassés.
     */
    static void ajusterTtl(byte[] m, long ecart) {
        if (ecart <= 0) {
            return;
        }
        try {
            int p = finQuestion(m);
            int an = nombreReponses(m) + nombreAutorites(m);
            for (int i = 0; i < an; i++) {
                p += longueurNom(m, p);
                if (p + 10 > m.length) {
                    return;
                }
                long ttl = ((long) (m[p + 4] & 0xff) << 24)
                        | ((long) (m[p + 5] & 0xff) << 16)
                        | ((long) (m[p + 6] & 0xff) << 8)
                        | (m[p + 7] & 0xff);
                long reste = Math.max(1L, ttl - ecart);
                m[p + 4] = (byte) (reste >> 24);
                m[p + 5] = (byte) (reste >> 16);
                m[p + 6] = (byte) (reste >> 8);
                m[p + 7] = (byte) reste;
                int rdlen = ((m[p + 8] & 0xff) << 8) | (m[p + 9] & 0xff);
                p += 10 + rdlen;
            }
        } catch (RuntimeException ignore) {
            // Réponse exotique : on la laisse telle quelle.
        }
    }

    static byte[] servfail(byte[] requete) {
        if (requete.length < 12) {
            return new byte[0];
        }
        byte[] r = new byte[Math.min(requete.length, 512)];
        r[0] = requete[0];
        r[1] = requete[1];
        r[2] = (byte) 0x81; // QR + RD
        r[3] = (byte) 0x82; // RA + SERVFAIL
        r[4] = 0;
        r[5] = 1;
        int fin;
        try {
            fin = Math.min(r.length, finQuestion(requete));
        } catch (RuntimeException e) {
            return new byte[0];
        }
        if (fin > 12) {
            System.arraycopy(requete, 12, r, 12, fin - 12);
        }
        return r;
    }
}
