'use strict';
'require view';
'require form';
'require uci';
'require fs';
'require ui';

return view.extend({
	load: function() {
		return uci.load('tordns');
	},

	render: function() {
		var m = new form.Map('tordns', _('TorDNS'),
			_('Relais DNS local vers Tor. Le service écoute seulement en boucle locale ; dnsmasq est le résolveur visible du LAN.'));
		var s = m.section(form.NamedSection, 'main', 'tordns', _('Réglages'));
		s.anonymous = true;
		var o;

		o = s.option(form.Flag, 'enabled', _('Activer le service'));
		o.default = '1';
		o.rmempty = false;

		o = s.option(form.Value, 'onion', _('Adresse .onion utilisée'));
		o.placeholder = 'cinquante-six-caracteres.onion';
		o.rmempty = true;

		o = s.option(form.ListValue, 'mode', _('Mode d’adresse'));
		o.value('coeur', _('Cœur seulement'));
		o.value('secours', _('Secours'));
		o.value('communaute', _('Communauté'));

		o = s.option(form.ListValue, 'dnssec', _('Validation DNSSEC'));
		o.value('auto', _('Automatique'));
		o.value('strict', _('Stricte'));
		o.value('non', _('Désactivée (déconseillé)'));

		o = s.option(form.Value, 'cache', _('Entrées de cache'));
		o.datatype = 'uinteger';
		o.default = '4096';

		o = s.option(form.Value, 'port', _('Port local du relais'));
		o.datatype = 'port';
		o.default = '5353';

		o = s.option(form.Flag, 'dnsmasq', _('Transférer dnsmasq vers le relais'));
		o.default = '1';

		o = s.option(form.Flag, 'anti_fuite', _('Bloquer DNS direct et DoT (853) du LAN'));
		o.default = '1';

		o = s.option(form.Value, 'lan_iface', _('Interface LAN'));
		o.default = 'br-lan';

		var sortie = E('pre', { 'style': 'white-space:pre-wrap;max-height:20rem;overflow:auto' }, '');
		var bouton = E('button', {
			'class': 'btn cbi-button cbi-button-action',
			'click': function(ev) {
				ev.preventDefault();
				sortie.textContent = _('Test en cours…');
				Promise.all([
					fs.exec('/usr/sbin/tordns-client', [ '-diagnostic' ]).catch(function(e) { return { code: -1, stdout: '', stderr: String(e) }; }),
					fs.exec('/usr/sbin/nft', [ 'list', 'chain', 'inet', 'fw4', 'tordns_anti_fuite' ]).catch(function(e) { return { code: -1, stdout: '', stderr: String(e) }; }),
					fs.exec('/etc/init.d/tordns', [ 'running' ]).catch(function(e) { return { code: -1, stdout: '', stderr: String(e) }; })
				]).then(function(r) {
					var etat = r[2].code === 0 ? _('Service actif') : _('Service arrêté ou en erreur');
					sortie.textContent = etat + '\n\n' + _('Diagnostic local :') + '\n' + (r[0].stdout || '') + (r[0].stderr || '') +
						'\n' + _('Chaîne nftables :') + '\n' + (r[1].stdout || r[1].stderr || _('absente'));
				});
			}
		}, _('Tester l’état et les fuites'));

		var panneau = E('div', { 'class': 'cbi-section' }, [
			E('h3', {}, _('État et test de fuite')),
			E('p', {}, _('Adresse configurée : ') + (uci.get('tordns', 'main', 'onion') || _('aucune'))),
			bouton,
			sortie
		]);

		return m.render().then(function(node) {
			node.appendChild(panneau);
			return node;
		});
	}
});
