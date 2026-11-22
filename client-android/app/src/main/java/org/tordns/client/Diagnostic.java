package org.tordns.client;

/** Diagnostic des fuites DNS propres à Android, sans dépendance au framework. */
final class Diagnostic {
    private Diagnostic() {}

    /**
     * Interprète le réglage « DNS privé » (DoT). Un mode opportuniste ou
     * strict fait passer les requêtes hors du VpnService : elles ne sont pas
     * capturées par TorDNS.
     */
    static String dnsPrive(String mode, String hote) {
        if (mode == null || mode.isEmpty() || "off".equals(mode)) {
            return "OK : DNS privé Android désactivé, aucun DoT hors tunnel détecté.";
        }
        if ("opportunistic".equals(mode)) {
            return "FUITE POSSIBLE : DNS privé Android en mode automatique. "
                    + "Le passer sur « Désactivé » (Paramètres → Réseau → DNS privé) "
                    + "pour que toutes les requêtes passent par TorDNS.";
        }
        String cible = hote == null || hote.isEmpty() ? "" : " (" + hote + ")";
        return "FUITE : DNS privé Android activé" + cible + ". "
                + "Ses requêtes DoT contournent le VpnService. "
                + "Le passer sur « Désactivé » et laisser TorDNS résoudre le DNS.";
    }
}
