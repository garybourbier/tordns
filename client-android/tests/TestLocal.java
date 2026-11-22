package org.tordns.client;

/** Vérifications exécutables sur la JVM, sans appareil ni Android. */
public final class TestLocal {
    private static int verifications;

    private static void attendre(boolean condition, String message) {
        verifications++;
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    private static byte[] requete(String domaine, int id, boolean dnssec) {
        java.io.ByteArrayOutputStream o = new java.io.ByteArrayOutputStream();
        o.write(id >> 8);
        o.write(id);
        o.write(0x01);
        o.write(0x00);
        o.write(0);
        o.write(1);
        for (int i = 0; i < 4; i++) {
            o.write(0); // an, ns
        }
        o.write(0); // ar : une OPT en mode DNSSEC
        o.write(dnssec ? 1 : 0);
        for (String partie : domaine.split("\\.")) {
            o.write(partie.length());
            o.writeBytes(partie.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1));
        }
        o.write(0);
        o.write(0);
        o.write(1);
        o.write(0);
        o.write(1);
        if (dnssec) {
            // OPT : nom racine, type 41, classe 1232, TTL avec DO, rdlen 0.
            o.write(0);
            o.write(0);
            o.write(41);
            o.write(0x04);
            o.write(0xd0);
            o.write(0);
            o.write(0);
            o.write(0x80);
            o.write(0);
            o.write(0);
            o.write(0);
        }
        return o.toByteArray();
    }

    private static byte[] reponsePositive(byte[] requete) {
        java.io.ByteArrayOutputStream o = new java.io.ByteArrayOutputStream();
        o.write(requete[0]);
        o.write(requete[1]);
        o.write(0x81);
        o.write(0x80);
        o.write(0);
        o.write(1);
        o.write(0);
        o.write(1);
        o.write(0);
        o.write(0);
        o.write(0);
        o.write(0);
        int finQuestion = DnsMessage.finQuestion(requete);
        o.write(requete, 12, finQuestion - 12);
        // Réponse : pointeur vers le nom de la question, A, IN, TTL 300, 4 octets.
        o.write(0xc0);
        o.write(12);
        o.write(0);
        o.write(1);
        o.write(0);
        o.write(1);
        o.write(0);
        o.write(0);
        o.write(1);
        o.write(0x2c);
        o.write(0);
        o.write(4);
        o.write(93);
        o.write(184);
        o.write(216);
        o.write(34);
        return o.toByteArray();
    }

    /** Paquet IPv4/UDP valide avec sommes correctes. */
    private static byte[] paquet(byte[] dns) {
        byte[] p = new byte[20 + 8 + dns.length];
        p[0] = 0x45;
        p[2] = (byte) (p.length >> 8);
        p[3] = (byte) p.length;
        p[8] = 64;
        p[9] = 17;
        byte[] src = {10, 111, (byte) 222, 2};
        byte[] dst = {10, 111, (byte) 222, 1};
        System.arraycopy(src, 0, p, 12, 4);
        System.arraycopy(dst, 0, p, 16, 4);
        int ip = 0xffff - Paquet.plier(Paquet.somme16(p, 0, 20));
        p[10] = (byte) (ip >> 8);
        p[11] = (byte) ip;

        p[20] = 0x30;
        p[21] = 0x39;
        p[22] = 0;
        p[23] = 53;
        p[24] = (byte) (p.length - 20 >> 8);
        p[25] = (byte) (p.length - 20);
        System.arraycopy(dns, 0, p, 28, dns.length);
        return p;
    }

    private static int ttl(byte[] reponse) {
        int p = DnsMessage.finQuestion(reponse) + DnsMessage.longueurNom(
                reponse, DnsMessage.finQuestion(reponse));
        return ((reponse[p + 4] & 0xff) << 24) | ((reponse[p + 5] & 0xff) << 16)
                | ((reponse[p + 6] & 0xff) << 8) | (reponse[p + 7] & 0xff);
    }

    public static void main(String[] args) throws Exception {
        byte[] q = requete("Example.COM", 0x1234, false);
        attendre("example.com".equals(DnsMessage.nom(q, 12)), "nom normalisé");
        attendre(DnsMessage.cle(q).equals("example.com|1|1|plain"), "clé de cache");
        attendre(!DnsMessage.demandeDnssec(q), "DO absent");
        attendre(DnsMessage.demandeDnssec(requete("example.com", 1, true)), "DO détecté");

        byte[] p = paquet(q);
        Paquet.Requete extraite = Paquet.extraire(p);
        attendre(extraite != null, "paquet DNS extrait");
        attendre(extraite.portSource == 0x3039 && extraite.portDestination == 53, "ports");
        attendre(java.util.Arrays.equals(extraite.dns, q), "charge utile intacte");
        attendre(Paquet.extraire(paquet(requete("example.com", 1, false))) != null, "second paquet");
        attendre(Paquet.reponse(p, extraite, q)[9] == 17, "réponse UDP");

        byte[] r = reponsePositive(q);
        byte[] sortant = Paquet.reponse(p, extraite, r);
        attendre(Paquet.plier(Paquet.somme16(sortant, 0, 20)) == 0xffff, "somme IP valide");
        attendre((sortant[12] & 0xff) == 10 && (sortant[16] & 0xff) == 10, "adresses échangées");
        attendre((sortant[20] & 0xff) == 0 && (sortant[22] & 0xff) == 0x30, "ports échangés");
        int udpLong = ((sortant[24] & 0xff) << 8) | (sortant[25] & 0xff);
        attendre(udpLong == 8 + r.length, "longueur UDP");
        attendre(sortant[28] == q[0] && sortant[29] == q[1], "id conservé");

        DnsCache cache = new DnsCache(4, 3600_000L);
        cache.poser(DnsMessage.cle(q), r);
        attendre(cache.taille() == 1, "entrée en cache");
        byte[] servi = cache.obtenir(DnsMessage.cle(q), 0x2222);
        attendre(servi != null && (servi[0] & 0xff) == 0x22 && (servi[1] & 0xff) == 0x22, "id réécrit");
        attendre(ttl(servi) >= 299 && ttl(servi) <= 300, "TTL rendu " + ttl(servi));
        Thread.sleep(2100);
        byte[] apres = cache.obtenir(DnsMessage.cle(q), 1);
        attendre(apres != null && ttl(apres) <= 298, "TTL décrémenté : " + ttl(apres));

        DnsCache petit = new DnsCache(2, 3600_000L);
        for (int i = 0; i < 5; i++) {
            petit.poser("cle" + i, reponsePositive(requete("h" + i + ".example", i, false)));
        }
        attendre(petit.taille() == 2, "LRU borné");

        byte[] sf = DnsMessage.servfail(q);
        attendre(DnsMessage.rcode(sf) == 2, "SERVFAIL");
        attendre((sf[2] & 0x80) != 0 && (sf[3] & 0x80) != 0, "drapeaux réponse");

        System.out.println("OK : " + verifications + " vérifications locales passées");
    }
}
