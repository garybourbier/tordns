package org.tordns.client;

import org.xbill.DNS.ARecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.DNSKEYRecord;
import org.xbill.DNS.DNSSEC;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.NSECRecord;
import org.xbill.DNS.Name;
import org.xbill.DNS.SOARecord;
import org.xbill.DNS.OPTRecord;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;
import org.xbill.DNS.Type;

import java.net.InetAddress;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Instant;

/** Tests JVM du validateur DNSSEC Android (dnsjava + mission 28). */
public final class TestDnssec {
    private static int verifications;

    private static void ok(boolean condition, String texte) {
        verifications++;
        if (!condition) {
            throw new AssertionError(texte);
        }
    }

    /** Transport qui ne signe QUE si le bit DO est posé sur la requête. */
    static final class TransportSigneSiDO implements Dnssec.Transport {
        private final DNSKEYRecord cle;
        private final org.xbill.DNS.RRSIGRecord sigCle;
        private final ARecord adresse;
        private final org.xbill.DNS.RRSIGRecord sigA;
        private final Name zone;
        private boolean dernierDoBit = false;

        TransportSigneSiDO(Name zone, DNSKEYRecord cle, org.xbill.DNS.RRSIGRecord sigCle,
                           ARecord adresse, org.xbill.DNS.RRSIGRecord sigA) {
            this.zone = zone;
            this.cle = cle;
            this.sigCle = sigCle;
            this.adresse = adresse;
            this.sigA = sigA;
        }

        boolean getDernierDoBit() { return dernierDoBit; }

        @Override
        public byte[] envoyer(byte[] requete) throws java.io.IOException {
            Message question = new Message(requete);
            // Vérifier si le bit DO est posé (dans l'OPT record)
            boolean doBit = false;
            for (Record rr : question.getSection(Section.ADDITIONAL)) {
                if (rr instanceof OPTRecord) {
                    OPTRecord opt = (OPTRecord) rr;
                    // Le bit DO est dans les flags de l'OPT record (bit 15 = 0x8000)
                    if ((opt.getFlags() & 0x8000) != 0) {
                        doBit = true;
                    }
                }
            }
            dernierDoBit = doBit;

            Message reponse = Dnssec.reponse(question);
            Record q = question.getQuestion();
            if (q.getType() == Type.DNSKEY) {
                reponse.addRecord(cle, Section.ANSWER);
                if (doBit) reponse.addRecord(sigCle, Section.ANSWER);
            } else if (q.getType() == Type.A) {
                reponse.addRecord(adresse, Section.ANSWER);
                if (doBit) reponse.addRecord(sigA, Section.ANSWER);
            } else {
                reponse.getHeader().setRcode(org.xbill.DNS.Rcode.NXDOMAIN);
            }
            return reponse.toWire();
        }
    }

    /** Transport qui répond une réponse négative signée (NXDOMAIN ou NODATA). */
    static final class TransportNegatif implements Dnssec.Transport {
        private final DNSKEYRecord cle;
        private final org.xbill.DNS.RRSIGRecord sigCle;
        private final Message negative;

        TransportNegatif(DNSKEYRecord cle, org.xbill.DNS.RRSIGRecord sigCle, Message negative) {
            this.cle = cle;
            this.sigCle = sigCle;
            this.negative = negative;
        }

        @Override
        public byte[] envoyer(byte[] requete) throws java.io.IOException {
            Message question = new Message(requete);
            if (question.getQuestion().getType() == Type.DNSKEY) {
                Message reponse = Dnssec.reponse(question);
                reponse.addRecord(cle, Section.ANSWER);
                reponse.addRecord(sigCle, Section.ANSWER);
                return reponse.toWire();
            }
            Message reponse = new Message(negative.toWire());
            reponse.getHeader().setID(question.getHeader().getID());
            return reponse.toWire();
        }
    }

    /** Message négatif signé : SOA et NSEC de la zone, chacun avec son RRSIG. */
    private static Message negatif(byte[] requete, int rcode, SOARecord soa,
            org.xbill.DNS.RRSIGRecord sigSoa, NSECRecord nsec, org.xbill.DNS.RRSIGRecord sigNsec)
            throws java.io.IOException {
        Message question = new Message(requete);
        Message reponse = new Message(question.getHeader().getID());
        reponse.getHeader().setFlag(Flags.QR);
        reponse.getHeader().setFlag(Flags.AA);
        reponse.getHeader().setRcode(rcode);
        reponse.addRecord(question.getQuestion(), Section.QUESTION);
        reponse.addRecord(soa, Section.AUTHORITY);
        reponse.addRecord(sigSoa, Section.AUTHORITY);
        reponse.addRecord(nsec, Section.AUTHORITY);
        reponse.addRecord(sigNsec, Section.AUTHORITY);
        return reponse;
    }

    /** Transport qui répond sans signature (zone non signée). */
    static final class TransportNonSigne implements Dnssec.Transport {
        private final ARecord adresse;
        private final Name zone;

        TransportNonSigne(Name zone, ARecord adresse) {
            this.zone = zone;
            this.adresse = adresse;
        }

        @Override
        public byte[] envoyer(byte[] requete) throws java.io.IOException {
            Message question = new Message(requete);
            Message reponse = Dnssec.reponse(question);
            Record q = question.getQuestion();
            if (q.getType() == Type.A) {
                reponse.addRecord(adresse, Section.ANSWER);
                // Pas de RRSIG, pas de DNSKEY = zone non signée
            } else {
                reponse.getHeader().setRcode(org.xbill.DNS.Rcode.NXDOMAIN);
            }
            return reponse.toWire();
        }
    }

    /** Fixture d'un cas commun : sa requête, son transport et son ancre. */
    static final class Fixture {
        final byte[] requete;
        final Dnssec.Transport transport;
        final RRset ancre;

        Fixture(byte[] requete, Dnssec.Transport transport, RRset ancre) {
            this.requete = requete;
            this.transport = transport;
            this.ancre = ancre;
        }
    }

    /** Verdict au vocabulaire du fichier de cas commun : accept / reject. */
    private static String classer(Dnssec.Transport transport, byte[] requete, RRset ancre) {
        try {
            Dnssec.valider(transport, requete, ancre);
            return "accept";
        } catch (java.io.IOException e) {
            return "reject";
        }
    }

    /**
     * Mission 28, point 4 : cas communs aux trois validateurs. Le fichier
     * testvectors/dnssec_vectors.json donne le verdict attendu par plateforme ;
     * ce test exécute les cas applicables à Android et échoue si un cas
     * applicable n'a pas de fixture, ou si le verdict observé diffère.
     */
    private static void vecteursCommuns(java.util.Map<String, Fixture> fixtures) throws Exception {
        String racine = System.getenv().getOrDefault("TOR_DNS_RACINE", ".");
        java.nio.file.Path chemin = java.nio.file.Paths.get(racine, "testvectors",
                "dnssec_vectors.json");
        java.util.List<String> lignes = java.nio.file.Files.readAllLines(chemin);
        java.util.List<String[]> cas = new java.util.ArrayList<>();
        String courant = null;
        for (String brute : lignes) {
            String ligne = brute.trim();
            if (ligne.startsWith("\"name\": \"")) {
                int fin = ligne.indexOf('"', 9);
                if (fin > 0) {
                    courant = ligne.substring(9, fin);
                }
            }
            int marque = ligne.indexOf("\"android\": \"");
            if (marque >= 0 && courant != null) {
                int debut = marque + 12;
                int fin = ligne.indexOf('"', debut);
                if (fin > 0) {
                    cas.add(new String[]{ courant, ligne.substring(debut, fin) });
                }
            }
        }
        ok(!cas.isEmpty(), "aucun cas lu dans " + chemin);
        for (String[] c : cas) {
            String nom = c[0];
            String attendu = c[1];
            Fixture fixture = fixtures.get(nom);
            if ("n/a".equals(attendu)) {
                ok(fixture == null, "cas " + nom + " : non applicable à Android mais une fixture existe");
                continue;
            }
            if (fixture == null) {
                ok(false, "cas " + nom + " : déclaré applicable à Android sans fixture");
                continue;
            }
            String obtenu = classer(fixture.transport, fixture.requete, fixture.ancre);
            ok(attendu.equals(obtenu), "cas " + nom + " : verdict " + obtenu + ", attendu " + attendu);
        }
        for (String nom : fixtures.keySet()) {
            boolean connu = false;
            for (String[] c : cas) {
                if (c[0].equals(nom)) {
                    connu = true;
                    break;
                }
            }
            ok(connu, "fixture " + nom + " sans cas correspondant dans le fichier commun");
        }
    }

    public static void main(String[] args) throws Exception {
        KeyPairGenerator generateur = KeyPairGenerator.getInstance("Ed25519");
        KeyPair paire = generateur.generateKeyPair();
        Name zone = Name.fromString("example.test.");
        DNSKEYRecord cle = new DNSKEYRecord(zone, DClass.IN, 3600, 257, 3,
                DNSSEC.Algorithm.ED25519, paire.getPublic());
        RRset ancre = Dnssec.ancre(cle);

        RRset dnskeys = new RRset();
        dnskeys.addRR(cle);
        org.xbill.DNS.RRSIGRecord sigCle = DNSSEC.sign(dnskeys, cle, paire.getPrivate(),
                Instant.now().minusSeconds(60), Instant.now().plusSeconds(3600));

        ARecord adresse = new ARecord(zone, DClass.IN, 60,
                InetAddress.getByAddress(new byte[]{ (byte) 192, 0, 2, 1 }));
        RRset a = new RRset();
        a.addRR(adresse);
        org.xbill.DNS.RRSIGRecord sigA = DNSSEC.sign(a, cle, paire.getPrivate(),
                Instant.now().minusSeconds(60), Instant.now().plusSeconds(3600));

        Message q = Message.newQuery(Record.newRecord(zone, Type.A, DClass.IN));

        // Test 1 : le résolveur pose le bit DO sur la requête sortante
        TransportSigneSiDO transport = new TransportSigneSiDO(zone, cle, sigCle, adresse, sigA);
        try {
            Dnssec.valider(transport, q.toWire(), ancre);
        } catch (java.io.IOException ignored) {
            // La validation peut échouer (chaîne incomplète), mais on vérifie le DO bit
        }
        ok(transport.getDernierDoBit(), "bit DO non posé sur la requête sortante");

        // Test 2 : zone NON signée (pas de DNSKEY, pas de RRSIG) -> REFUS (mission 28)
        Dnssec.Transport nonSigne = new TransportNonSigne(zone, adresse);
        boolean refuse = false;
        try {
            Dnssec.valider(nonSigne, q.toWire(), ancre);
        } catch (java.io.IOException e) {
            refuse = true;
        }
        ok(refuse, "réponse d'une zone non signée acceptée (devrait être refusée)");

        // Test 3 : transport qui NE pose PAS le bit DO -> le nœud ne signe pas -> refus
        Dnssec.Transport sansDO = requete -> {
            Message question = new Message(requete);
            Message reponse = Dnssec.reponse(question);
            Record r = question.getQuestion();
            if (r.getType() == Type.DNSKEY) {
                reponse.addRecord(cle, Section.ANSWER);
            } else if (r.getType() == Type.A) {
                reponse.addRecord(adresse, Section.ANSWER);
            }
            return reponse.toWire();
        };
        refuse = false;
        try {
            Dnssec.valider(sansDO, q.toWire(), ancre);
        } catch (java.io.IOException e) {
            refuse = true;
        }
        ok(refuse, "réponse sans DO bit acceptée (nœud ne signe pas sans DO)");

        // Test 4 : adresse modifiée après signature -> refusée
        ARecord fausse = new ARecord(zone, DClass.IN, 60,
                InetAddress.getByAddress(new byte[]{ (byte) 203, 0, 113, 9 }));
        Dnssec.Transport menteur = new TransportSigneSiDO(zone, cle, sigCle, fausse, sigA);
        refuse = false;
        try {
            Dnssec.valider(menteur, q.toWire(), ancre);
        } catch (java.io.IOException e) {
            refuse = true;
        }
        ok(refuse, "réponse à fausse adresse acceptée");

        // Test 5 : signature absente sur A (DO posé mais réponse sans RRSIG sur A) -> refusée
        Dnssec.Transport sansSigA = requete -> {
            Message question = new Message(requete);
            Message reponse = Dnssec.reponse(question);
            Record r = question.getQuestion();
            if (r.getType() == Type.DNSKEY) {
                reponse.addRecord(cle, Section.ANSWER);
                reponse.addRecord(sigCle, Section.ANSWER);
            } else if (r.getType() == Type.A) {
                reponse.addRecord(adresse, Section.ANSWER);
                // Pas de RRSIG sur A
            }
            return reponse.toWire();
        };
        refuse = false;
        try {
            Dnssec.valider(sansSigA, q.toWire(), ancre);
        } catch (java.io.IOException e) {
            refuse = true;
        }
        ok(refuse, "réponse sans RRSIG sur A acceptée");

        // Test 6 : les DEUX ancres du roulement sont livrées et lisibles.
        // En retirer une casserait soit la racine actuelle, soit les clients
        // qui n'ont pas encore reçu l'ancre suivante.
        String[] ancres = Dnssec.ancresLivrees();
        ok(ancres.length == 2, "ancres livrées : " + ancres.length + " au lieu de 2");
        int[] tagsAttendus = { 20326, 38696 };
        for (int i = 0; i < ancres.length; i++) {
            Record ds = Record.fromString(new Name("."), Type.DS, DClass.IN, 0,
                    new org.xbill.DNS.Tokenizer(ancres[i]), null);
            ok(ds instanceof org.xbill.DNS.DSRecord, "ancre " + i + " n'est pas un DS");
            ok(((org.xbill.DNS.DSRecord) ds).getFootprint() == tagsAttendus[i],
                    "ancre " + i + " : key tag " + ((org.xbill.DNS.DSRecord) ds).getFootprint()
                            + ", attendu " + tagsAttendus[i]);
        }

        // Test 7 : signature authentique mais hors de sa période de validité
        Instant debutPasse = Instant.now().minusSeconds(7200);
        Instant finPasse = Instant.now().minusSeconds(3600);
        org.xbill.DNS.RRSIGRecord sigCleExpiree = DNSSEC.sign(dnskeys, cle, paire.getPrivate(),
                debutPasse, finPasse);
        org.xbill.DNS.RRSIGRecord sigAExpiree = DNSSEC.sign(a, cle, paire.getPrivate(),
                debutPasse, finPasse);
        Dnssec.Transport expire = new TransportSigneSiDO(zone, cle, sigCleExpiree, adresse, sigAExpiree);

        // Test 8 : signature valide, mais faite par une autre zone que le nom
        // signé (attaque cross-zone). L'ancre est la clé de la zone attaquante :
        // même ancrée, une signature ne peut pas couvrir le nom d'une autre zone.
        Name zoneAttaquant = Name.fromString("attaquant.test.");
        KeyPair paireAttaquant = generateur.generateKeyPair();
        DNSKEYRecord cleAttaquant = new DNSKEYRecord(zoneAttaquant, DClass.IN, 3600, 257, 3,
                DNSSEC.Algorithm.ED25519, paireAttaquant.getPublic());
        RRset dnskeysAttaquant = new RRset();
        dnskeysAttaquant.addRR(cleAttaquant);
        org.xbill.DNS.RRSIGRecord sigCleAttaquant = DNSSEC.sign(dnskeysAttaquant, cleAttaquant,
                paireAttaquant.getPrivate(), Instant.now().minusSeconds(60),
                Instant.now().plusSeconds(3600));
        Name victime = Name.fromString("victime.test.");
        ARecord adresseVictime = new ARecord(victime, DClass.IN, 60,
                InetAddress.getByAddress(new byte[]{ (byte) 198, 51, 100, 7 }));
        RRset aVictime = new RRset();
        aVictime.addRR(adresseVictime);
        org.xbill.DNS.RRSIGRecord sigVictime = DNSSEC.sign(aVictime, cleAttaquant,
                paireAttaquant.getPrivate(), Instant.now().minusSeconds(60),
                Instant.now().plusSeconds(3600));
        Dnssec.Transport crossZone = new TransportSigneSiDO(zoneAttaquant, cleAttaquant,
                sigCleAttaquant, adresseVictime, sigVictime);
        byte[] qVictime = Message.newQuery(Record.newRecord(victime, Type.A, DClass.IN)).toWire();

        // Test 9 : réponses négatives signées (NXDOMAIN et NODATA)
        SOARecord soa = new SOARecord(zone, DClass.IN, 300,
                Name.fromString("ns.example.test."),
                Name.fromString("hostmaster.example.test."),
                1, 3600, 600, 86400, 300);
        RRset soaSet = new RRset();
        soaSet.addRR(soa);
        Instant debutValide = Instant.now().minusSeconds(60);
        Instant finValide = Instant.now().plusSeconds(3600);
        org.xbill.DNS.RRSIGRecord sigSoa = DNSSEC.sign(soaSet, cle, paire.getPrivate(),
                debutValide, finValide);

        // NXDOMAIN : le nom absent tombe entre le sommet de zone et zzz.
        NSECRecord nsecAbsent = new NSECRecord(zone, DClass.IN, 300,
                Name.fromString("zzz.example.test."), new int[]{ Type.NS, Type.SOA });
        RRset nsecAbsentSet = new RRset();
        nsecAbsentSet.addRR(nsecAbsent);
        org.xbill.DNS.RRSIGRecord sigNsecAbsent = DNSSEC.sign(nsecAbsentSet, cle,
                paire.getPrivate(), debutValide, finValide);
        byte[] qAbsent = Message.newQuery(Record.newRecord(
                Name.fromString("absent.example.test."), Type.A, DClass.IN)).toWire();
        Message nx = negatif(qAbsent, org.xbill.DNS.Rcode.NXDOMAIN, soa, sigSoa,
                nsecAbsent, sigNsecAbsent);

        // NODATA : le nom existe, le bitmap n'annonce pas A.
        Name present = Name.fromString("www.example.test.");
        NSECRecord nsecPresent = new NSECRecord(present, DClass.IN, 300,
                Name.fromString("zzz.example.test."),
                new int[]{ Type.NS, Type.SOA, Type.TXT });
        RRset nsecPresentSet = new RRset();
        nsecPresentSet.addRR(nsecPresent);
        org.xbill.DNS.RRSIGRecord sigNsecPresent = DNSSEC.sign(nsecPresentSet, cle,
                paire.getPrivate(), debutValide, finValide);
        byte[] qPresent = Message.newQuery(Record.newRecord(present, Type.A, DClass.IN)).toWire();
        Message nodata = negatif(qPresent, org.xbill.DNS.Rcode.NOERROR, soa, sigSoa,
                nsecPresent, sigNsecPresent);

        Dnssec.Transport transportNx = new TransportNegatif(cle, sigCle, nx);
        Dnssec.Transport transportNodata = new TransportNegatif(cle, sigCle, nodata);

        // Test 10 : une preuve qui ne couvre pas le nom est refusée (pas
        // d'acceptation d'un NXDOMAIN sur la seule présence d'un NSEC).
        NSECRecord nsecHors = new NSECRecord(Name.fromString("aaa.example.test."),
                DClass.IN, 300, Name.fromString("bbb.example.test."),
                new int[]{ Type.NS, Type.SOA });
        RRset nsecHorsSet = new RRset();
        nsecHorsSet.addRR(nsecHors);
        org.xbill.DNS.RRSIGRecord sigNsecHors = DNSSEC.sign(nsecHorsSet, cle,
                paire.getPrivate(), debutValide, finValide);
        Message nxFaux = negatif(qAbsent, org.xbill.DNS.Rcode.NXDOMAIN, soa, sigSoa,
                nsecHors, sigNsecHors);
        ok("reject".equals(classer(new TransportNegatif(cle, sigCle, nxFaux), qAbsent, ancre)),
                "NXDOMAIN accepté avec un NSEC hors intervalle");

        // Test 11 : un NODATA dont le NSEC annonce le type demandé est refusé.
        NSECRecord nsecAnnonceA = new NSECRecord(present, DClass.IN, 300,
                Name.fromString("zzz.example.test."),
                new int[]{ Type.A, Type.NS, Type.SOA });
        RRset nsecAnnonceASet = new RRset();
        nsecAnnonceASet.addRR(nsecAnnonceA);
        org.xbill.DNS.RRSIGRecord sigNsecAnnonceA = DNSSEC.sign(nsecAnnonceASet, cle,
                paire.getPrivate(), debutValide, finValide);
        Message nodataFaux = negatif(qPresent, org.xbill.DNS.Rcode.NOERROR, soa, sigSoa,
                nsecAnnonceA, sigNsecAnnonceA);
        ok("reject".equals(classer(new TransportNegatif(cle, sigCle, nodataFaux), qPresent, ancre)),
                "NODATA accepté dont le NSEC annonce le type demandé");

        // Test 12 : cas de conformité communs aux trois validateurs
        java.util.Map<String, Fixture> fixtures = new java.util.LinkedHashMap<>();
        fixtures.put("signed_zone_valid", new Fixture(q.toWire(), transport, ancre));
        fixtures.put("unsigned_zone_nsec_proves_no_ds", new Fixture(q.toWire(), nonSigne, ancre));
        fixtures.put("unsigned_zone_nsec3_opt_out", new Fixture(q.toWire(), nonSigne, ancre));
        fixtures.put("forged_address_in_signed_zone", new Fixture(q.toWire(), menteur, ancre));
        fixtures.put("missing_signature_on_signed_zone", new Fixture(q.toWire(), sansSigA, ancre));
        fixtures.put("expired_signature", new Fixture(q.toWire(), expire, ancre));
        fixtures.put("signature_by_wrong_zone", new Fixture(qVictime, crossZone,
                Dnssec.ancre(cleAttaquant)));
        fixtures.put("no_do_bit_request", new Fixture(q.toWire(), sansDO, ancre));
        fixtures.put("nxdomain_with_nsec_proof", new Fixture(qAbsent, transportNx, ancre));
        fixtures.put("nodata_with_nsec_proof", new Fixture(qPresent, transportNodata, ancre));
        vecteursCommuns(fixtures);

        System.out.println("OK : " + verifications + " vérifications DNSSEC Android passées");
    }
}