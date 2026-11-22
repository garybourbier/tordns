package org.tordns.client;

/** Analyse et construction des paquets IPv4/UDP du tunnel, sans dépendance Android. */
final class Paquet {
    private Paquet() {}

    /** Vue sur une requête DNS transportée en UDP. */
    static final class Requete {
        final int ihl;
        final int portSource;
        final int portDestination;
        final byte[] dns;

        Requete(int ihl, int portSource, int portDestination, byte[] dns) {
            this.ihl = ihl;
            this.portSource = portSource;
            this.portDestination = portDestination;
            this.dns = dns;
        }
    }

    /** Renvoie la requête DNS si le paquet est un IPv4/UDP vers le port 53, sinon null. */
    static Requete extraire(byte[] p) {
        if (p == null || p.length < 28 || (p[0] >> 4) != 4) {
            return null;
        }
        int ihl = (p[0] & 0x0f) * 4;
        if (ihl < 20 || p.length < ihl + 8 || p[9] != 17) {
            return null;
        }
        int total = ((p[2] & 0xff) << 8) | (p[3] & 0xff);
        if (total < ihl + 8 || total > p.length) {
            return null;
        }
        int dstPort = ((p[ihl + 2] & 0xff) << 8) | (p[ihl + 3] & 0xff);
        int srcPort = ((p[ihl] & 0xff) << 8) | (p[ihl + 1] & 0xff);
        if (dstPort != 53) {
            return null;
        }
        int udpLong = ((p[ihl + 4] & 0xff) << 8) | (p[ihl + 5] & 0xff);
        if (udpLong < 8 || ihl + udpLong > total) {
            return null;
        }
        byte[] requete = new byte[udpLong - 8];
        System.arraycopy(p, ihl + 8, requete, 0, requete.length);
        if (requete.length < 12 || (requete[2] & 0x80) != 0) {
            return null;
        }
        return new Requete(ihl, srcPort, dstPort, requete);
    }

    /** Construit le paquet de réponse en échangeant adresses, ports et sommes. */
    static byte[] reponse(byte[] p, Requete requete, byte[] dns) {
        int ihl = requete.ihl;
        int taille = ihl + 8 + dns.length;
        byte[] r = new byte[taille];
        System.arraycopy(p, 0, r, 0, ihl);
        r[2] = (byte) (taille >> 8);
        r[3] = (byte) taille;
        r[8] = 64;
        for (int i = 0; i < 4; i++) {
            byte t = r[12 + i];
            r[12 + i] = r[16 + i];
            r[16 + i] = t;
        }
        r[10] = 0;
        r[11] = 0;
        int somme = ~plier(somme16(r, 0, ihl)) & 0xffff;
        r[10] = (byte) (somme >> 8);
        r[11] = (byte) somme;

        r[ihl] = (byte) (requete.portDestination >> 8);
        r[ihl + 1] = (byte) requete.portDestination;
        r[ihl + 2] = (byte) (requete.portSource >> 8);
        r[ihl + 3] = (byte) requete.portSource;
        int udpLong = 8 + dns.length;
        r[ihl + 4] = (byte) (udpLong >> 8);
        r[ihl + 5] = (byte) udpLong;
        r[ihl + 6] = 0;
        r[ihl + 7] = 0;
        System.arraycopy(dns, 0, r, ihl + 8, dns.length);

        int pseudo = 17 + udpLong;
        for (int i = 12; i < 20; i += 2) {
            pseudo += ((r[i] & 0xff) << 8) | (r[i + 1] & 0xff);
        }
        int sommeUdp = ~plier(somme16(r, ihl, udpLong) + pseudo) & 0xffff;
        if (sommeUdp == 0) {
            sommeUdp = 0xffff;
        }
        r[ihl + 6] = (byte) (sommeUdp >> 8);
        r[ihl + 7] = (byte) sommeUdp;
        return r;
    }

    /** Replie une somme en 16 bits (complément à un). */
    static int plier(int somme) {
        while ((somme >>> 16) != 0) {
            somme = (somme & 0xffff) + (somme >>> 16);
        }
        return somme;
    }

    static int somme16(byte[] b, int offset, int longueur) {
        int somme = 0;
        int i = offset;
        int fin = offset + longueur;
        while (i + 1 < fin) {
            somme += ((b[i] & 0xff) << 8) | (b[i + 1] & 0xff);
            i += 2;
        }
        if (i < fin) {
            somme += (b[i] & 0xff) << 8;
        }
        return plier(somme);
    }
}
