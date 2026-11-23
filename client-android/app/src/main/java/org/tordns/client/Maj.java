package org.tordns.client;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.Locale;

/**
 * Mise à jour Android (mission 12).
 *
 * Hors Play, Android interdit à une application de se remplacer seule. On
 * vérifie donc le manifeste signé en arrière-plan, on télécharge l'APK par Tor,
 * on contrôle son SHA-256, puis on affiche une notification. Au toucher, une
 * session PackageInstaller demande l'accord de l'utilisateur ; l'APK doit être
 * signé avec la même clé que la version installée, sinon Android refuse.
 */
final class Maj {
    static final String ACTION_INSTALLER = "org.tordns.client.INSTALLER";
    private static final String PREFS = "tordns";
    private static final String CHANNEL = "maj";
    private static final int NOTIFICATION = 42;
    private static final int TAILLE_MAX_APK = 128 * 1024 * 1024;

    private Maj() {}

    interface Ecouteur {
        void surResultat(String message);
    }

    /** Chemin du cache de la dernière mise à jour vérifiée. */
    static File dossier(Context contexte) {
        File d = new File(contexte.getFilesDir(), "maj");
        d.mkdirs();
        return d;
    }

    static File apk(Context contexte) {
        return new File(dossier(contexte), "tordns-client.apk");
    }

    /** Lance la vérification hors du fil d'interface. */
    static void verifier(Context contexte, String onion, Ecouteur ecouteur) {
        Thread fil = new Thread(() -> {
            String message;
            try {
                message = verifierBloquant(contexte, onion);
            } catch (Exception e) {
                message = "mise à jour impossible : " + e.getMessage();
            }
            final String resultat = message;
            new android.os.Handler(contexte.getMainLooper()).post(() -> {
                if (ecouteur != null) {
                    ecouteur.surResultat(resultat);
                }
            });
        }, "maj-android");
        fil.setDaemon(true);
        fil.start();
    }

    private static String verifierBloquant(Context contexte, String onion)
            throws IOException, InterruptedException {
        if (onion == null || !onion.endsWith(".onion")) {
            throw new IOException("adresse .onion absente");
        }
        Resolveur resolveur = Resolveur.INSTANCE;
        if (!resolveur.pret()) {
            resolveur.configurer(onion);
            resolveur.demarrer(contexte.getApplicationContext(), null);
            long limite = System.currentTimeMillis() + 180_000L;
            while (!resolveur.pret() && System.currentTimeMillis() < limite) {
                Thread.sleep(2_000L);
            }
        }
        if (!resolveur.pret()) {
            throw new IOException("Tor non démarré : " + resolveur.etat());
        }

        byte[] manifeste = telecharger(onion, "/maj/manifeste.json", 64 * 1024);
        byte[] signature = telecharger(onion, "/maj/manifeste.json.sig", 4096);
        if (manifeste == null || signature == null) {
            throw new IOException("manifeste ou signature absent du miroir");
        }
        long installee = versionInstallee(contexte);
        String record = Arti.verifierManifeste(
                manifeste, signature, installee, System.currentTimeMillis() / 1000L);
        if (record == null) {
            throw new IOException("manifeste refusé : " + Arti.derniereErreur());
        }
        String[] champs = record.split("\\|", -1);
        if (champs.length < 5) {
            throw new IOException("réponse de vérification illisible");
        }
        long version = Long.parseLong(champs[0]);
        String url = champs[1];
        long taille = Long.parseLong(champs[2]);
        String sha = champs[3];

        File dossier = dossier(contexte);
        ecrire(new File(dossier, "manifeste.json"), manifeste);
        ecrire(new File(dossier, "manifeste.json.sig"), signature);

        String chemin = cheminDuMiroir(url, onion);
        byte[] apk = telecharger(onion, chemin, TAILLE_MAX_APK);
        if (apk == null) {
            throw new IOException("APK absent du miroir");
        }
        if (apk.length != taille) {
            throw new IOException("taille de l'APK : " + apk.length + ", attendu " + taille);
        }
        if (!sha.equals(empreinte(apk))) {
            throw new IOException("SHA-256 de l'APK différent du manifeste");
        }
        File cible = new File(dossier, "tordns-client.apk.nouveau");
        ecrire(cible, apk);
        File ancien = apk(contexte);
        if (!cible.renameTo(ancien)) {
            throw new IOException("remplacement de l'APK impossible");
        }
        notifier(contexte, version);
        return "Mise à jour v" + version + " vérifiée : toucher la notification pour installer";
    }

    private static byte[] telecharger(String onion, String chemin, int max) {
        return Arti.telecharger(onion, chemin, max);
    }

    /** Refuse une URL qui ne désigne pas le miroir du nœud configuré. */
    static String cheminDuMiroir(String url, String onion) throws IOException {
        Uri u = Uri.parse(url);
        if (!"http".equals(u.getScheme()) || !onion.equals(u.getHost())) {
            throw new IOException("URL de mise à jour hors du nœud Tor");
        }
        String chemin = u.getPath();
        if (chemin == null || !chemin.startsWith("/maj/")) {
            throw new IOException("chemin de mise à jour invalide");
        }
        return chemin;
    }

    @SuppressWarnings("deprecation") // versionCode reste le seul champ avant API 28
    private static long versionInstallee(Context contexte) {
        try {
            PackageInfo info = contexte.getPackageManager()
                    .getPackageInfo(contexte.getPackageName(), 0);
            return Build.VERSION.SDK_INT >= 28 ? info.getLongVersionCode() : info.versionCode;
        } catch (PackageManager.NameNotFoundException e) {
            return 0;
        }
    }

    private static void ecrire(File fichier, byte[] octets) throws IOException {
        File tmp = new File(fichier.getParentFile(), fichier.getName() + ".tmp");
        try (FileOutputStream sortie = new FileOutputStream(tmp)) {
            sortie.write(octets);
            sortie.getFD().sync();
        }
        try {
            Files.move(tmp.toPath(), fichier.toPath(),
                    java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            if (!tmp.renameTo(fichier)) {
                throw e;
            }
        }
    }

    static String empreinte(byte[] octets) throws IOException {
        try {
            byte[] somme = MessageDigest.getInstance("SHA-256").digest(octets);
            StringBuilder b = new StringBuilder(64);
            for (byte o : somme) {
                b.append(String.format(Locale.ROOT, "%02x", o));
            }
            return b.toString();
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IOException("SHA-256 indisponible", e);
        }
    }

    @SuppressWarnings("deprecation") // constructeur sans canal avant API 26
    private static void notifier(Context contexte, long version) {
        NotificationManager nm = contexte.getSystemService(NotificationManager.class);
        if (nm == null) {
            return;
        }
        if (Build.VERSION.SDK_INT >= 26) {
            NotificationChannel canal = new NotificationChannel(
                    CHANNEL, "Mises à jour", NotificationManager.IMPORTANCE_DEFAULT);
            canal.setDescription("Mises à jour vérifiées du client TorDNS");
            nm.createNotificationChannel(canal);
        }
        Intent installation = new Intent(contexte, InstallateurMaj.class)
                .setAction(ACTION_INSTALLER)
                .putExtra("apk", apk(contexte).getAbsolutePath());
        PendingIntent action = PendingIntent.getBroadcast(contexte, 1, installation,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        Notification.Builder b = Build.VERSION.SDK_INT >= 26
                ? new Notification.Builder(contexte, CHANNEL)
                : new Notification.Builder(contexte);
        b.setSmallIcon(android.R.drawable.stat_sys_download_done)
                .setContentTitle("TorDNS " + version + " prête")
                .setContentText("Toucher pour installer la mise à jour vérifiée")
                .setContentIntent(action)
                .setAutoCancel(true);
        try {
            nm.notify(NOTIFICATION, b.build());
        } catch (SecurityException e) {
            // Notification refusée par l'utilisateur : le message à l'écran
            // reste la seule indication, aucune installation silencieuse.
            android.util.Log.w("TorDNS", "notification de mise à jour refusée");
        }
    }

    /**
     * Adresses cœur/communauté du dernier manifeste vérifié, ou null. Utilisé
     * au démarrage pour choisir l'adresse sans la coder en dur.
     */
    static String[] adressesVerifiees(Context contexte) {
        try {
            File dossier = dossier(contexte);
            byte[] manifeste = lire(new File(dossier, "manifeste.json"));
            byte[] signature = lire(new File(dossier, "manifeste.json.sig"));
            if (manifeste == null || signature == null) {
                return null;
            }
            String record = Arti.verifierManifeste(manifeste, signature, 0,
                    System.currentTimeMillis() / 1000L);
            if (record == null) {
                return null;
            }
            String[] champs = record.split("\\|", -1);
            if (champs.length < 7) {
                return null;
            }
            return new String[]{champs[5], champs[6]};
        } catch (Exception e) {
            return null;
        }
    }

    private static byte[] lire(File f) throws IOException {
        if (!f.isFile()) {
            return null;
        }
        try (InputStream entree = Files.newInputStream(f.toPath())) {
            java.io.ByteArrayOutputStream sortie = new java.io.ByteArrayOutputStream();
            byte[] bloc = new byte[8192];
            int n;
            while ((n = entree.read(bloc)) > 0) {
                sortie.write(bloc, 0, n);
                if (sortie.size() > 64 * 1024) {
                    throw new IOException("manifeste trop gros");
                }
            }
            return sortie.toByteArray();
        }
    }

    /** Choix de l'adresse selon le réglage ; le cœur reste le défaut. */
    static String choisirAdresse(String manuelle, String mode, String coeur, String communaute) {
        boolean c = coeur != null && coeur.endsWith(".onion");
        boolean m = communaute != null && communaute.endsWith(".onion");
        if ("communaute".equals(mode)) {
            return m ? communaute : (c ? coeur : manuelle);
        }
        if ("secours".equals(mode)) {
            return c ? coeur : (manuelle != null && !manuelle.isEmpty() ? manuelle
                    : (m ? communaute : manuelle));
        }
        // « cœur seulement » ne bascule jamais silencieusement sur un bénévole.
        return c ? coeur : manuelle;
    }

    static SharedPreferences preferences(Context contexte) {
        return contexte.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }
}
