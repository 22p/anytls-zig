'use strict';
'require view';
'require form';

return view.extend({
	render: function() {
		var m, s, o;

		m = new form.Map('anytls-zig', _('AnyTLS Zig'),
			_('AnyTLS (protocol v2) client with a SOCKS5 inbound. TLS 1.3 with certificate chain and hostname verification.'));

		s = m.section(form.NamedSection, 'main', 'anytls-zig', _('Settings'));
		s.anonymous = true;
		s.addremove = false;

		o = s.option(form.Flag, 'enabled', _('Enable'));
		o.default = '0';
		o.rmempty = false;
		o.description = _('Start the client automatically when the system boots.');

		o = s.option(form.Value, 'listen', _('SOCKS5 listen address'));
		o.datatype = 'hostport';
		o.placeholder = '127.0.0.1:1080';
		o.default = '127.0.0.1:1080';
		o.description = _('Use 0.0.0.0:1080 to serve the LAN; the default listens on loopback only.');

		o = s.option(form.Value, 'server', _('Server address'));
		o.datatype = 'hostport';
		o.placeholder = 'example.com:443';
		o.rmempty = false;

		o = s.option(form.Value, 'sni', _('TLS server name (SNI)'));
		o.datatype = 'hostname';
		o.placeholder = 'example.com';
		o.description = _('Leave empty to use the server host name.');

		o = s.option(form.Value, 'password', _('Password'));
		o.password = true;
		o.rmempty = false;
		o.description = _('Stored in /etc/config/anytls-zig; keep that file readable by root only.');

		o = s.option(form.Value, 'ca', _('CA bundle'));
		o.placeholder = '/etc/ssl/certs/ca-certificates.crt';
		o.datatype = 'file';
		o.description = _('Empty uses the system CA bundle from the ca-bundle package.');

		o = s.option(form.Flag, 'insecure', _('Disable TLS verification'),
			_('DANGER: disables certificate chain and hostname checks. Do not enable in production.'));
		o.default = '0';
		o.rmempty = false;

		o = s.option(form.Value, 'connect_timeout', _('Connect timeout'),
			_('Seconds (1-300).'));
		o.datatype = 'range(1,300)';
		o.default = '10';

		o = s.option(form.Value, 'min_idle', _('Warm idle sessions'),
			_('Sessions kept ready (0-64).'));
		o.datatype = 'range(0,64)';
		o.default = '5';

		o = s.option(form.Value, 'idle_timeout', _('Idle timeout'),
			_('Seconds before an idle session is closed (5-86400).'));
		o.datatype = 'range(5,86400)';
		o.default = '30';

		o = s.option(form.Value, 'max_streams', _('Streams per session'),
			_('Concurrent streams multiplexed on one session (1-4096).'));
		o.datatype = 'range(1,4096)';
		o.default = '128';

		o = s.option(form.Value, 'half_close_wait', _('Half-close grace'),
			_('Seconds to wait for the peer FIN after a local half close (0-3600).'));
		o.datatype = 'range(0,3600)';
		o.default = '3';

		o = s.option(form.ListValue, 'log_level', _('Log level'));
		o.value('error', _('Error'));
		o.value('warn', _('Warning'));
		o.value('info', _('Info'));
		o.value('debug', _('Debug'));
		o.default = 'info';

		return m.render();
	}
});
