package org.tordns.client;

import org.xbill.DNS.ARecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.DNSKEYRecord;
import org.xbill.DNS.DNSSEC;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;
import org.xbill.DNS.Type;

import java.net.InetAddress;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Instant;

/** Tests JVM du validateur DNSSEC Android (dnsjava). */
public final class TestDnssec {
    private static int verifications;

    private static void ok(boolean condition, String texte) {
        verifications++;
        if (!condition) {
            throw new AssertionError(texte);
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

        Dnssec.Transport transport = requete -> {
            Message question = new Message(requete);
            Message reponse = Dnssec.reponse(question);
            Record q = question.getQuestion();
            if (q.getType() == Type.DNSKEY) {
                reponse.addRecord(cle, Section.ANSWER);
                reponse.addRecord(sigCle, Section.ANSWER);
            } else if (q.getType() == Type.A) {
                reponse.addRecord(adresse, Section.ANSWER);
                reponse.addRecord(sigA, Section.ANSWER);
            } else {
                reponse.getHeader().setRcode(org.xbill.DNS.Rcode.NXDOMAIN);
            }
            return reponse.toWire();
        };

        Message q = Message.newQuery(Record.newRecord(zone, Type.A, DClass.IN));
        byte[] valide = Dnssec.valider(transport, q.toWire(), ancre);
        Message lue = new Message(valide);
        ok(lue.getHeader().getFlag(Flags.AD), "réponse signée non marquée AD");
        ok(!lue.getSection(Section.ANSWER).isEmpty(), "réponse A absente");

        // Adresse modifiée après signature : le vérificateur doit refuser.
        ARecord fausse = new ARecord(zone, DClass.IN, 60,
                InetAddress.getByAddress(new byte[]{ (byte) 203, 0, 113, 9 }));
        Dnssec.Transport menteur = requete -> {
            Message question = new Message(requete);
            Message reponse = Dnssec.reponse(question);
            Record r = question.getQuestion();
            if (r.getType() == Type.DNSKEY) {
                reponse.addRecord(cle, Section.ANSWER);
                reponse.addRecord(sigCle, Section.ANSWER);
            } else if (r.getType() == Type.A) {
                reponse.addRecord(fausse, Section.ANSWER);
                reponse.addRecord(sigA, Section.ANSWER);
            }
            return reponse.toWire();
        };
        boolean refuse = false;
        try {
            Dnssec.valider(menteur, q.toWire(), ancre);
        } catch (java.io.IOException e) {
            refuse = true;
        }
        ok(refuse, "réponse à fausse adresse acceptée");

        // Signature absente : refus également.
        Dnssec.Transport sansSig = requete -> {
            Message question = new Message(requete);
            Message reponse = Dnssec.reponse(question);
            Record r = question.getQuestion();
            if (r.getType() == Type.DNSKEY) {
                reponse.addRecord(cle, Section.ANSWER);
                reponse.addRecord(sigCle, Section.ANSWER);
            } else if (r.getType() == Type.A) {
                reponse.addRecord(adresse, Section.ANSWER);
            }
            return reponse.toWire();
        };
        refuse = false;
        try {
            Dnssec.valider(sansSig, q.toWire(), ancre);
        } catch (java.io.IOException e) {
            refuse = true;
        }
        ok(refuse, "réponse sans RRSIG acceptée");

        System.out.println("OK : " + verifications + " vérifications DNSSEC Android passées");
    }
}
