package org.tordns.client;

import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.VpnService;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.InputType;
import android.view.Gravity;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.util.Locale;
import java.util.Random;

/** Écran unique : configuration, activation du VPN et preuve de résolution. */
public class MainActivity extends Activity {
    private static final int DEMANDE_VPN = 1;
    private static final String PREFS = "tordns";

    private EditText champOnion;
    private EditText champDomaine;
    private RadioButton modeDns;
    private RadioButton modeFuite;
    private Button boutonVpn;
    private TextView statut;
    private TextView moteur;
    private TextView stats;
    private final Handler boucle = new Handler(Looper.getMainLooper());

    private final Runnable rafraichir = new Runnable() {
        @Override
        public void run() {
            Resolveur r = Resolveur.INSTANCE;
            statut.setText(r.etat());
            stats.setText(String.format(Locale.ROOT,
                    "Requêtes : %d   cache : %d   erreurs : %d   entrées : %d",
                    r.total(), r.hits(), r.erreurs(), r.tailleCache()));
            boutonVpn.setText(TorVpnService.actif() ? "Désactiver la protection" : "Activer la protection");
            boucle.postDelayed(this, 1000);
        }
    };

    @Override
    protected void onCreate(Bundle sauvegarde) {
        super.onCreate(sauvegarde);
        SharedPreferences p = getSharedPreferences(PREFS, MODE_PRIVATE);

        ScrollView defilement = new ScrollView(this);
        LinearLayout racine = new LinearLayout(this);
        racine.setOrientation(LinearLayout.VERTICAL);
        int marge = (int) (20 * getResources().getDisplayMetrics().density);
        racine.setPadding(marge, marge, marge, marge);
        defilement.addView(racine);

        TextView titre = new TextView(this);
        titre.setText("TorDNS");
        titre.setTextSize(26);
        racine.addView(titre);

        TextView explication = new TextView(this);
        explication.setText("Les requêtes DNS sont capturées localement (sans root), "
                + "puis résolues via le service caché Tor. Aucun journal, aucun nom de domaine conservé.");
        explication.setPadding(0, marge / 2, 0, marge);
        racine.addView(explication);

        racine.addView(etiquette("Adresse du service .onion"));
        champOnion = new EditText(this);
        champOnion.setHint("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.onion");
        champOnion.setSingleLine(true);
        champOnion.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI);
        champOnion.setText(p.getString("onion", ""));
        racine.addView(champOnion);

        racine.addView(etiquette("Mode de protection"));
        RadioGroup groupes = new RadioGroup(this);
        modeDns = new RadioButton(this);
        modeDns.setText("DNS du système uniquement");
        modeFuite = new RadioButton(this);
        modeFuite.setText("Anti-fuite (résolveurs publics connus détournés)");
        groupes.addView(modeDns);
        groupes.addView(modeFuite);
        (p.getBoolean("antifuite", false) ? modeFuite : modeDns).setChecked(true);
        racine.addView(groupes);

        boutonVpn = new Button(this);
        boutonVpn.setText("Activer la protection");
        boutonVpn.setOnClickListener(v -> basculerVpn(p));
        racine.addView(boutonVpn);

        racine.addView(etiquette("Test de résolution (hors VPN)"));
        champDomaine = new EditText(this);
        champDomaine.setHint("example.com");
        champDomaine.setSingleLine(true);
        champDomaine.setInputType(InputType.TYPE_CLASS_TEXT);
        racine.addView(champDomaine);

        Button tester = new Button(this);
        tester.setText("Résoudre via Tor");
        tester.setOnClickListener(v -> tester());
        racine.addView(tester);

        statut = new TextView(this);
        statut.setText(Resolveur.INSTANCE.etat());
        statut.setPadding(0, marge, 0, 0);
        racine.addView(statut);

        // Force le chargement de la bibliothèque JNI dès l'ouverture : un
        // problème d'ABI ou de symbole est ainsi visible avant tout VPN.
        moteur = new TextView(this);
        try {
            Arti.derniereErreur();
            moteur.setText("Moteur Tor (Arti/JNI) chargé");
            android.util.Log.i("TorDNS", "bibliothèque Arti chargée");
        } catch (Throwable t) {
            moteur.setText("Moteur Tor indisponible : " + t);
            android.util.Log.e("TorDNS", "chargement Arti impossible : " + t);
        }
        racine.addView(moteur);

        stats = new TextView(this);
        racine.addView(stats);

        TextView note = new TextView(this);
        note.setText("\nLe domaine saisi n'est utilisé que pour ce test et n'est jamais journalisé. "
                + "Le premier démarrage de Tor peut prendre une minute.");
        note.setTextSize(12);
        racine.addView(note);

        setContentView(defilement);

        boucle.post(rafraichir);
    }

    private TextView etiquette(String texte) {
        TextView t = new TextView(this);
        t.setText(texte);
        t.setPadding(0, (int) (12 * getResources().getDisplayMetrics().density), 0, 4);
        t.setGravity(Gravity.START);
        t.setLayoutParams(new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        return t;
    }

    private void basculerVpn(SharedPreferences p) {
        if (TorVpnService.actif()) {
            startService(new Intent(this, TorVpnService.class).setAction(TorVpnService.ACTION_STOP));
            return;
        }
        String onion = champOnion.getText().toString().trim().toLowerCase(Locale.ROOT);
        if (!onion.endsWith(".onion") || onion.length() < 16) {
            Toast.makeText(this, "Adresse .onion invalide", Toast.LENGTH_LONG).show();
            return;
        }
        p.edit().putString("onion", onion)
                .putBoolean("antifuite", modeFuite.isChecked())
                .apply();
        Resolveur.INSTANCE.configurer(onion);

        Intent preparation = VpnService.prepare(this);
        if (preparation != null) {
            startActivityForResult(preparation, DEMANDE_VPN);
        } else {
            demarrerService();
        }
    }

    @Override
    protected void onActivityResult(int requete, int resultat, Intent donnees) {
        super.onActivityResult(requete, resultat, donnees);
        if (requete == DEMANDE_VPN && resultat == RESULT_OK) {
            demarrerService();
        } else if (requete == DEMANDE_VPN) {
            Toast.makeText(this, "Autorisation VPN refusée", Toast.LENGTH_LONG).show();
        }
    }

    private void demarrerService() {
        Intent i = new Intent(this, TorVpnService.class)
                .setAction(TorVpnService.ACTION_START)
                .putExtra(TorVpnService.EXTRA_ONION, Resolveur.INSTANCE.onion())
                .putExtra(TorVpnService.EXTRA_ANTIFUITE, modeFuite.isChecked());
        if (android.os.Build.VERSION.SDK_INT >= 26) {
            startForegroundService(i);
        } else {
            startService(i);
        }
    }

    private void tester() {
        Resolveur r = Resolveur.INSTANCE;
        String onion = champOnion.getText().toString().trim().toLowerCase(Locale.ROOT);
        if (!onion.endsWith(".onion")) {
            Toast.makeText(this, "Renseignez d'abord l'adresse .onion", Toast.LENGTH_LONG).show();
            return;
        }
        r.configurer(onion);
        if (!r.pret()) {
            r.demarrer(getApplicationContext(), null);
            Toast.makeText(this, "Bootstrap Tor lancé, réessayez dans un instant", Toast.LENGTH_LONG).show();
            return;
        }
        String domaine = champDomaine.getText().toString().trim();
        if (domaine.isEmpty()) {
            domaine = "example.com";
        }
        final String domaineFinal = domaine;
        new Thread(() -> {
            long debut = System.nanoTime();
            byte[] requete = requeteA(domaineFinal);
            byte[] reponse = r.resoudre(requete);
            long ms = (System.nanoTime() - debut) / 1_000_000L;
            String resume = String.format(Locale.ROOT,
                    "rcode %d, %d réponse(s), %d ms", DnsMessage.rcode(reponse),
                    DnsMessage.nombreReponses(reponse), ms);
            runOnUiThread(() -> statut.setText("Test : " + resume));
        }, "test-dns").start();
    }

    private static byte[] requeteA(String domaine) {
        java.io.ByteArrayOutputStream sortie = new java.io.ByteArrayOutputStream();
        sortie.write(new Random().nextInt(65536) >> 8);
        sortie.write(new Random().nextInt(256));
        sortie.write(0x01);
        sortie.write(0x00);
        sortie.write(0);
        sortie.write(1);
        for (int i = 0; i < 6; i++) {
            sortie.write(0);
        }
        String[] parties = domaine.split("\\.");
        for (String partie : parties) {
            byte[] p = partie.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
            sortie.write(p.length);
            sortie.write(p, 0, p.length);
        }
        sortie.write(0);
        sortie.write(0);
        sortie.write(1);
        sortie.write(0);
        sortie.write(1);
        return sortie.toByteArray();
    }

    @Override
    protected void onDestroy() {
        boucle.removeCallbacks(rafraichir);
        super.onDestroy();
    }
}
