package org.tordns.client;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * VPN local sans root : aucun trafic n'est routé vers Internet, seules les
 * requêtes DNS sont interceptées sur le descripteur TUN et traitées par
 * {@link Resolveur}. Le paquet réponse est réinjecté tel quel.
 *
 * L'application elle-même est exclue du VPN (addDisallowedApplication) : Arti
 * a besoin du résolveur système pour joindre le réseau Tor, sans quoi le
 * bootstrap dépendrait de la résolution qu'il doit fournir (interblocage).
 * Ce résolveur système est donc la seule requête DNS qui ne soit pas capturée.
 */
public class TorVpnService extends VpnService {
    static final String ACTION_START = "org.tordns.client.START";
    static final String ACTION_STOP = "org.tordns.client.STOP";
    static final String EXTRA_ONION = "onion";
    static final String EXTRA_ANTIFUITE = "antifuite";

    private static final String CANAL = "tordns";
    private static final int NOTIF = 1;

    /** Vrai tant que le tunnel est établi (utilisé par l'interface). */
    static boolean actif() {
        return EN_SERVICE.get();
    }
    // L'adresse locale du TUN et celle du résolveur doivent différer : les
    // paquets sortants des applications ont pour source l'adresse du TUN.
    private static final String ADRESSE_LOCALE = "10.111.222.2";
    private static final String ADRESSE_DNS = "10.111.222.1";
    private static final int MTU = 1500;

    private static final String[] RESOLVEURS_CONNUS = {
            "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
            "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220",
    };

    private static final java.util.concurrent.atomic.AtomicBoolean EN_SERVICE =
            new java.util.concurrent.atomic.AtomicBoolean(false);
    private volatile boolean actif;
    private ParcelFileDescriptor tunnel;
    private Thread lecteur;
    private FileOutputStream sortie;

    @Override
    public int onStartCommand(Intent intent, int flags, int demarrage) {
        if (intent == null) {
            return START_NOT_STICKY;
        }
        if (ACTION_STOP.equals(intent.getAction())) {
            arreter();
            return START_NOT_STICKY;
        }
        if (!ACTION_START.equals(intent.getAction()) || actif) {
            return START_STICKY;
        }

        String onion = intent.getStringExtra(EXTRA_ONION);
        boolean antifuite = intent.getBooleanExtra(EXTRA_ANTIFUITE, false);
        Resolveur.INSTANCE.configurer(onion);
        if (Resolveur.INSTANCE.onion().isEmpty()) {
            return START_NOT_STICKY;
        }

        Builder b = new Builder();
        b.setSession("TorDNS");
        b.setMtu(MTU);
        b.addAddress(ADRESSE_LOCALE, 32);
        b.addDnsServer(ADRESSE_DNS);
        b.addRoute(ADRESSE_DNS, 32);
        b.setBlocking(true);
        try {
            b.addDisallowedApplication(getPackageName());
        } catch (Exception ignore) {
            // Le paquet est toujours présent ; cas théorique seulement.
        }
        if (antifuite) {
            // Capture aussi les requêtes envoyées en dur à des résolveurs connus.
            // Les autres flux vers ces adresses (DoH, etc.) sont volontairement
            // coupés : c'est le prix de l'anti-fuite sans NAT complet.
            for (String ip : RESOLVEURS_CONNUS) {
                try {
                    b.addRoute(InetAddress.getByName(ip), 32);
                } catch (UnknownHostException ignore) {
                    // Adresse littérale : ne peut pas échouer.
                }
            }
        }

        try {
            tunnel = b.establish();
        } catch (Exception e) {
            tunnel = null;
        }
        if (tunnel == null) {
            return START_NOT_STICKY;
        }

        actif = true;
        EN_SERVICE.set(true);
        notifier();
        Resolveur.INSTANCE.demarrer(this, null);
        lancerLecture();
        return START_STICKY;
    }

    private void lancerLecture() {
        // Les constructeurs sur FileDescriptor ne lèvent pas d'IOException :
        // une erreur de lecture termine simplement la boucle.
        FileInputStream entree = new FileInputStream(tunnel.getFileDescriptor());
        sortie = new FileOutputStream(tunnel.getFileDescriptor());
        lecteur = new Thread(() -> boucle(entree), "tun-lecture");
        lecteur.setDaemon(true);
        lecteur.start();
    }

    private void boucle(FileInputStream entree) {
        byte[] paquet = new byte[MTU];
        while (actif) {
            int n;
            try {
                n = entree.read(paquet);
            } catch (IOException e) {
                break;
            }
            if (n <= 0) {
                continue;
            }
            byte[] copie = new byte[n];
            System.arraycopy(paquet, 0, copie, 0, n);
            Resolveur.INSTANCE.pool().execute(() -> traiter(copie));
        }
    }

    /** Analyse un paquet IPv4/UDP ; ignore tout ce qui n'est pas du DNS entrant. */
    private void traiter(byte[] p) {
        Paquet.Requete requete = Paquet.extraire(p);
        if (requete == null) {
            return;
        }
        byte[] reponse;
        try {
            reponse = Resolveur.INSTANCE.resoudre(requete.dns);
        } catch (RuntimeException e) {
            reponse = DnsMessage.servfail(requete.dns);
        }
        if (reponse == null || reponse.length == 0) {
            return;
        }
        byte[] sortant = Paquet.reponse(p, requete, reponse);
        synchronized (this) {
            if (!actif || sortie == null) {
                return;
            }
            try {
                sortie.write(sortant);
            } catch (IOException ignore) {
                // TUN fermé : le service s'arrête de lui-même.
            }
        }
    }

    private void notifier() {
        NotificationManager nm = getSystemService(NotificationManager.class);
        if (Build.VERSION.SDK_INT >= 26) {
            NotificationChannel canal = new NotificationChannel(
                    CANAL, getString(R.string.canal_nom), NotificationManager.IMPORTANCE_LOW);
            canal.setDescription(getString(R.string.canal_desc));
            nm.createNotificationChannel(canal);
        }
        Intent ouvrir = new Intent(this, MainActivity.class);
        PendingIntent pi = PendingIntent.getActivity(this, 0, ouvrir,
                PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        Notification n = new Notification.Builder(this, CANAL)
                .setContentTitle(getString(R.string.notif_titre))
                .setContentText(getString(R.string.notif_texte))
                .setSmallIcon(android.R.drawable.ic_lock_lock)
                .setContentIntent(pi)
                .setOngoing(true)
                .build();
        startForeground(NOTIF, n);
    }

    private void arreter() {
        actif = false;
        EN_SERVICE.set(false);
        synchronized (this) {
            try {
                if (sortie != null) {
                    sortie.close();
                }
            } catch (IOException ignore) {
                // déjà fermé
            }
            try {
                if (tunnel != null) {
                    tunnel.close();
                }
            } catch (IOException ignore) {
                // déjà fermé
            }
            tunnel = null;
            sortie = null;
        }
        stopForeground(STOP_FOREGROUND_REMOVE);
        stopSelf();
    }

    @Override
    public void onRevoke() {
        arreter();
        super.onRevoke();
    }

    @Override
    public void onDestroy() {
        arreter();
        super.onDestroy();
    }
}
