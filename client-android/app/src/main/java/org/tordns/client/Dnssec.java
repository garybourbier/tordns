package org.tordns.client;

import org.xbill.DNS.DNSKEYRecord;
import org.xbill.DNS.DNSSEC;
import org.xbill.DNS.EDNSOption;
import org.xbill.DNS.ExtendedErrorCodeOption;
import org.xbill.DNS.Flags;
import org.xbill.DNS.OPTRecord;
import org.xbill.DNS.Record;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.RRset;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.Section;
import org.xbill.DNS.TSIG;
import org.xbill.DNS.dnssec.ValidatingResolver;

import java.io.IOException;
import java.time.Duration;
import java.util.List;

/**
 * Validation DNSSEC côté Android (mission 12).
 *
 * dnsjava construit la chaîne DS/DNSKEY jusqu'aux ancres racine et vérifie les
 * signatures ; aucune cryptographie n'est réimplémentée ici. Les requêtes de
 * validation passent par le même circuit Tor que la requête utilisateur.
 *
 * Le transport est injectable : les tests JVM utilisent une table de réponses
 * signées, l'application utilise le JNI Arti.
 */
final class Dnssec {
    private Dnssec() {}

    interface Transport {
        byte[] envoyer(byte[] requete) throws IOException;
    }

    /** Résolveur minimal : un paquet DNS brut par appel, via Tor. */
    static final class ResolveurTor implements Resolver {
        private final Transport transport;
        private Duration timeout = Duration.ofSeconds(20);

        ResolveurTor(Transport transport) {
            this.transport = transport;
        }

        @Override
        public void setPort(int port) {}

        @Override
        public void setTCP(boolean flag) {}

        @Override
        public void setIgnoreTruncation(boolean flag) {}

        @Override
        public void setEDNS(int level, int payloadSize, int flags, List<EDNSOption> options) {}

        @Override
        public void setTSIGKey(TSIG key) {}

        @Override
        public void setTimeout(Duration duree) {
            this.timeout = duree;
        }

        @Override
        public Duration getTimeout() {
            return timeout;
        }

        @Override
        public Message send(Message requete) throws IOException {
            byte[] brut = transport.envoyer(requete.toWire());
            if (brut == null) {
                throw new IOException("Tor n'a pas répondu");
            }
            return new Message(brut);
        }

        @Override
        public java.util.concurrent.CompletionStage<Message> sendAsync(
                Message requete, java.util.concurrent.Executor executeur) {
            // Le validateur dnsjava enchaîne les requêtes en asynchrone ; sans
            // cette redéfinition, l'implémentation par défaut se rappelle
            // elle-même en boucle.
            return java.util.concurrent.CompletableFuture.supplyAsync(() -> {
                try {
                    return send(requete);
                } catch (IOException e) {
                    throw new java.util.concurrent.CompletionException(e);
                }
            }, executeur);
        }
    }

    /** Validation de production, transport Arti. */
    static byte[] valider(String onion, byte[] requete) throws IOException {
        return valider(new Transport() {
            @Override
            public byte[] envoyer(byte[] paquet) {
                return Arti.doh(onion, paquet, 20000);
            }
        }, requete, null);
    }

    /**
     * Variante testable. {@code ancre} remplace les ancres racine pour un test
     * hors ligne ; en production, passer null pour utiliser la racine IANA.
     */
    static byte[] valider(Transport transport, byte[] requete, RRset ancre)
            throws IOException {
        ValidatingResolver validateur = new ValidatingResolver(new ResolveurTor(transport));
        validateur.setAddReasonToAdditional(true);
        if (ancre != null) {
            validateur.getTrustAnchors().clear();
            validateur.getTrustAnchors().store(ancre);
        }
        Message reponse = validateur.send(new Message(requete));
        // dnsjava peut renvoyer la réponse avec un motif EDE au lieu de lever
        // une exception. Une zone non signée n'a ni AD ni motif ; une réponse
        // signée fausse porte DNSSEC_BOGUS et doit être refusée.
        for (Record rr : reponse.getSection(Section.ADDITIONAL)) {
            if (!(rr instanceof OPTRecord)) {
                continue;
            }
            for (EDNSOption option : ((OPTRecord) rr).getOptions()) {
                if (option instanceof ExtendedErrorCodeOption) {
                    int code = ((ExtendedErrorCodeOption) option).getErrorCode();
                    // Une zone non signée ne produit aucun motif EDE. Tout
                    // motif signale une validation impossible : signature
                    // fausse, RRSIG/DNSKEY/NSEC manquant, etc.
                    if (code != ExtendedErrorCodeOption.OTHER) {
                        throw new IOException("réponse DNSSEC refusée (EDE " + code + ")");
                    }
                }
            }
        }
        return reponse.toWire();
    }

    /** Construit une ancre DNSKEY à partir d'un enregistrement de test. */
    static RRset ancre(DNSKEYRecord cle) {
        RRset rrset = new RRset();
        rrset.addRR(cle);
        return rrset;
    }

    /** Nom d'une zone signée, pour les tests. */
    static Name nom(String texte) throws IOException {
        return Name.fromString(texte);
    }

    /** Vérifie une signature hors du résolveur, pour les tests de fixture. */
    static void verifier(RRset rrset, org.xbill.DNS.RRSIGRecord sig, DNSKEYRecord cle)
            throws DNSSEC.DNSSECException {
        DNSSEC.verify(rrset, sig, cle);
    }

    static Message reponse(Message requete) {
        Message reponse = new Message(requete.getHeader().getID());
        reponse.getHeader().setFlag(Flags.QR);
        reponse.getHeader().setFlag(Flags.AA);
        reponse.addRecord(requete.getQuestion(), Section.QUESTION);
        return reponse;
    }
}
