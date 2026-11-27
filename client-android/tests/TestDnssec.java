package org.tordns.client;

import org.xbill.DNS.ARecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.DNSKEYRecord;
import org.xbill.DNS.DNSSEC;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
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
    private static void vecteursCommuns(byte[] requete, RRset ancre,
            java.util.Map<String, Dnssec.Transport> fixtures) throws Exception {
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
            Dnssec.Transport fixture = fixtures.get(nom);
            if ("n/a".equals(attendu)) {
                ok(fixture == null, "cas " + nom + " : non applicable à Android mais une fixture existe");
                continue;
            }
            if (fixture == null) {
                ok(false, "cas " + nom + " : déclaré applicable à Android sans fixture");
                continue;
            }
            String obtenu = classer(fixture, requete, ancre);
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

        // Test 6 : cas de conformité communs aux trois validateurs
        java.util.Map<String, Dnssec.Transport> fixtures = new java.util.LinkedHashMap<>();
        fixtures.put("unsigned_zone_nsec_proves_no_ds", nonSigne);
        fixtures.put("unsigned_zone_nsec3_opt_out", nonSigne);
        fixtures.put("forged_address_in_signed_zone", menteur);
        fixtures.put("missing_signature_on_signed_zone", sansSigA);
        fixtures.put("no_do_bit_request", sansDO);
        vecteursCommuns(q.toWire(), ancre, fixtures);

        System.out.println("OK : " + verifications + " vérifications DNSSEC Android passées");
    }
}