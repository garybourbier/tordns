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

        System.out.println("OK : " + verifications + " vérifications DNSSEC Android passées");
    }
}