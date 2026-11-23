package org.tordns.client;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageInstaller;
import android.widget.Toast;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Réception du toucher de notification et du résultat d'installation.
 *
 * La session PackageInstaller affiche la confirmation Android : l'application
 * ne peut jamais s'installer silencieusement hors Play. Le système vérifie en
 * plus que l'APK est signé par la même clé que la version en place.
 */
public class InstallateurMaj extends BroadcastReceiver {
    static final String ACTION_RETOUR = "org.tordns.client.RETOUR_INSTALLATION";

    @Override
    public void onReceive(Context contexte, Intent intention) {
        if (intention == null) {
            return;
        }
        if (Maj.ACTION_INSTALLER.equals(intention.getAction())) {
            String chemin = intention.getStringExtra("apk");
            if (chemin == null) {
                return;
            }
            installer(contexte, new File(chemin));
        } else if (ACTION_RETOUR.equals(intention.getAction())) {
            int statut = intention.getIntExtra(PackageInstaller.EXTRA_STATUS,
                    PackageInstaller.STATUS_FAILURE);
            String message = statut == PackageInstaller.STATUS_SUCCESS
                    ? "Mise à jour installée"
                    : "Installation refusée ou échouée (code " + statut + ")";
            Toast.makeText(contexte, message, Toast.LENGTH_LONG).show();
        }
    }

    private void installer(Context contexte, File apk) {
        try {
            PackageInstaller gestionnaire = contexte.getPackageManager().getPackageInstaller();
            PackageInstaller.SessionParams parametres = new PackageInstaller.SessionParams(
                    PackageInstaller.SessionParams.MODE_FULL_INSTALL);
            parametres.setAppPackageName(contexte.getPackageName());
            int session = gestionnaire.createSession(parametres);
            PackageInstaller.Session s = gestionnaire.openSession(session);
            try {
                try (InputStream entree = new FileInputStream(apk);
                     OutputStream sortie = s.openWrite("base.apk", 0, -1)) {
                    byte[] bloc = new byte[64 * 1024];
                    int n;
                    while ((n = entree.read(bloc)) > 0) {
                        sortie.write(bloc, 0, n);
                    }
                    sortie.flush();
                    s.fsync(sortie);
                }
                Intent retour = new Intent(contexte, InstallateurMaj.class)
                        .setAction(ACTION_RETOUR);
                android.app.PendingIntent attente = android.app.PendingIntent.getBroadcast(
                        contexte, 2, retour,
                        android.app.PendingIntent.FLAG_UPDATE_CURRENT
                                | android.app.PendingIntent.FLAG_MUTABLE);
                s.commit(attente.getIntentSender());
            } finally {
                s.close();
            }
        } catch (Exception e) {
            Toast.makeText(contexte, "Installation impossible : " + e.getMessage(),
                    Toast.LENGTH_LONG).show();
        }
    }
}
