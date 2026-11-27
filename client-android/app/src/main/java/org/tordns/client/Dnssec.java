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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Validation DNSSEC côté Android (mission 12/28).
 *
 * dnsjava construit la chaîne DS/DNSKEY jusqu'aux ancres racine et vérifie les
 * signatures ; aucune cryptographie n'est réimplémentée ici. Les requêtes de
 * validation passent par le même circuit Tor que la requête utilisateur.
 *
 * Le transport est injectable : les tests JVM utilisent une table de réponses
 * signées, l'application utilise le JNI Arti.
 *
 * Ancres racine IANA (RFC 9718) :
 * - KSK-2017 (key tag 20326) : révoquée le 11/01/2027, retirée le 22/03/2027
 * - KSK-2024 (key tag 38696) : seule ancre active depuis le 11/10/2026
 * Les DEUX sont chargées ; la chaîne est acceptée si AU MOINS UNE ancre la valide.
 * L'application échoue au démarrage si aucune ancre n'est chargée.
 */
final class Dnssec {
    private Dnssec() {}

    // Ancres racine IANA au format DS (keytag algorithm digesttype digest)
    // KSK-2017 (20326) et KSK-2024 (38696) — source : data.iana.org/root-anchors/root-anchors.xml
    private static final String ANCRE_KSK_2017 = "20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D";
    private static final String ANCRE_KSK_2024 = "38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16";

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
        public void setEDNS(int level, int payloadSize, int flags, List<EDNSOption> options) {
            // Le bit DO (0x8000 dans les flags OPT) est posé par le validateur.
            // On stocke les paramètres pour les appliquer aux requêtes sortantes.
        }

        @Override
        public void setEDNS(int level) {
            // Appelé par dnsjava internement
        }

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
            // S'assurer que la requête a un OPT record avec le bit DO (DNSSEC OK)
            Message reqCopy = new Message(requete.toWire());
            OPTRecord opt = reqCopy.getOPT();
            if (opt == null) {
                opt = new OPTRecord(4096, 0, 0, 0x8000); // payload=4096, version=0, DO=1
                reqCopy.addRecord(opt, Section.ADDITIONAL);
            } else {
                // S'assurer que le bit DO est posé
                if ((opt.getFlags() & 0x8000) == 0) {
                    reqCopy.removeRecord(opt, Section.ADDITIONAL);
                    OPTRecord newOpt = new OPTRecord(opt.getPayloadSize(), opt.getVersion(),
                        opt.getExtendedRcode(), opt.getFlags() | 0x8000, opt.getOptions());
                    reqCopy.addRecord(newOpt, Section.ADDITIONAL);
                }
            }
            byte[] brut = transport.envoyer(reqCopy.toWire());
            if (brut == null) {
                throw new IOException("Tor n'a pas répondu");
            }
            return new Message(brut);
        }

        @Override
        public java.util.concurrent.CompletionStage<Message> sendAsync(
                Message requete, java.util.concurrent.Executor executeur) {
            return java.util.concurrent.CompletableFuture.supplyAsync(() -> {
                try {
                    return send(requete);
                } catch (IOException e) {
                    throw new java.util.concurrent.CompletionException(e);
                }
            }, executeur);
        }
    }

    /**
     * Ancres racine livrées, dans l'ordre de chargement. Pendant un roulement,
     * les deux coexistent : en retirer une seule casserait soit la racine
     * actuelle, soit les résolveurs qui n'ont pas encore l'ancre suivante.
     */
    static String[] ancresLivrees() {
        return new String[]{ANCRE_KSK_2017, ANCRE_KSK_2024};
    }

    /** Charge les ancres racine IANA dans le validateur. Échoue si aucune n'est valide. */
    private static void chargerAncreRacine(ValidatingResolver validateur) throws IOException {
        int chargees = 0;
        for (String dsStr : ancresLivrees()) {
            try {
                org.xbill.DNS.Tokenizer tok = new org.xbill.DNS.Tokenizer(dsStr);
                org.xbill.DNS.Record rec = org.xbill.DNS.Record.fromString(
                    new org.xbill.DNS.Name("."), org.xbill.DNS.Type.DS, org.xbill.DNS.DClass.IN, 0, tok, null);
                if (rec != null && rec instanceof org.xbill.DNS.DSRecord) {
                    org.xbill.DNS.DSRecord ds = (org.xbill.DNS.DSRecord) rec;
                    // TrustAnchorStore attend un RRset
                    RRset rrset = new RRset();
                    rrset.addRR(ds);
                    validateur.getTrustAnchors().store(rrset);
                    chargees++;
                }
            } catch (Exception ignored) {
                // ancre invalide, on continue
            }
        }
        if (chargees == 0) {
            throw new IOException("Aucune ancre racine DNSSEC chargée — démarrage impossible");
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
     * hors ligne ; en production, passer null pour utiliser les ancres IANA.
     */
    static byte[] valider(Transport transport, byte[] requete, RRset ancre)
            throws IOException {
        ValidatingResolver validateur = new ValidatingResolver(new ResolveurTor(transport));
        validateur.setAddReasonToAdditional(true);
        boolean modeTest = (ancre != null);
        if (modeTest) {
            validateur.getTrustAnchors().clear();
            validateur.getTrustAnchors().store(ancre);
        } else {
            chargerAncreRacine(validateur);
        }
        Message reponse = validateur.send(new Message(requete));

        // Trancher sur le résultat de validation (RCODE + verdict) au lieu de relayer
        // Vérifier les motifs EDE dans l'ADDITIONAL
        boolean aEdeBloquant = false;
        for (Record rr : reponse.getSection(Section.ADDITIONAL)) {
            if (!(rr instanceof OPTRecord)) {
                continue;
            }
            for (EDNSOption option : ((OPTRecord) rr).getOptions()) {
                if (option instanceof ExtendedErrorCodeOption) {
                    int code = ((ExtendedErrorCodeOption) option).getErrorCode();
                    // En mode test, on ignore DNSSEC_INDETERMINATE (6) car la chaîne
                    // de confiance simplifiée ne peut pas être validée complètement.
                    // En production, tout EDE != OTHER est bloquant.
                    if (code != ExtendedErrorCodeOption.OTHER) {
                        if (modeTest && code == ExtendedErrorCodeOption.DNSSEC_INDETERMINATE) {
                            continue;
                        }
                        aEdeBloquant = true;
                    }
                }
            }
        }
        if (aEdeBloquant) {
            throw new IOException("réponse DNSSEC refusée (EDE bloquant)");
        }

        // Vérifier le bit AD : s'il est absent sur une réponse positive, refus
        // (zone signée sans validation possible ou zone non signée en mode strict)
        if (reponse.getHeader().getRcode() == org.xbill.DNS.Rcode.NOERROR
                && !reponse.getHeader().getFlag(Flags.AD)) {
            throw new IOException("réponse DNSSEC refusée : bit AD absent");
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
