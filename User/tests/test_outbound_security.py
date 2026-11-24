"""Task 4: SSRF protection. Mocked DNS and transports only -- nothing is contacted."""

import os
from unittest import mock

from django.test import SimpleTestCase, override_settings

from User.security import outbound
from User.security.outbound import OutboundBlocked, OutboundError, safe_request, validate_url

from .helpers import fake_resolver


class _FakeResp:
    def __init__(self, status=200, headers=None, body=b'<html><title>t</title></html>'):
        self.status = status
        self.headers = headers or {'Content-Type': 'text/html; charset=utf-8'}
        self._body = body

    def stream(self, n):
        yield self._body

    def release_conn(self):
        pass


class _FakePool:
    """Records the pinned IP / Host header and replays scripted responses."""

    def __init__(self, script, log):
        self.script, self.log = script, log

    def __call__(self, target, ip, connect_timeout, read_timeout):
        self.log.append((target.host, ip))
        pool = mock.MagicMock()
        pool.urlopen.side_effect = lambda method, path, headers, **kw: self.script.pop(0)
        return pool


class OutboundBase(SimpleTestCase):
    def setUp(self):
        outbound.set_resolver(fake_resolver)
        self.addCleanup(outbound.set_resolver, None)


class URLPolicyTests(OutboundBase):
    def test_public_destination_allowed(self):
        target = validate_url('https://www.example.com/a?b=1')
        self.assertEqual(target.addresses, ['93.184.216.34'])
        self.assertEqual(target.port, 443)

    def test_unsafe_schemes_rejected(self):
        for url in ['ftp://example.com/', 'file:///etc/passwd', 'gopher://example.com', 'javascript:alert(1)',
                    'data:text/html,x']:
            with self.assertRaises(OutboundBlocked, msg=url):
                validate_url(url)

    def test_credentials_rejected(self):
        with self.assertRaises(OutboundBlocked) as ctx:
            validate_url('http://user:pass@example.com/')
        self.assertEqual(ctx.exception.reason, 'credentials_in_url')

    def test_ports(self):
        validate_url('http://example.com:8080/')
        for url in ['http://example.com:22/', 'http://example.com:6379/', 'http://example.com:0/',
                    'http://example.com:99999/', 'http://example.com:abc/']:
            with self.assertRaises(OutboundBlocked, msg=url):
                validate_url(url)

    def test_custom_port_policy(self):
        with mock.patch.dict(os.environ, {'OUTBOUND_ALLOWED_PORTS': '443'}):
            with self.assertRaises(OutboundBlocked):
                validate_url('http://example.com/')

    def test_forbidden_ip_literals(self):
        for url in ['http://127.0.0.1/', 'http://10.1.2.3/', 'http://172.16.0.1/', 'http://192.168.0.1/',
                    'http://169.254.169.254/latest/meta-data/', 'http://0.0.0.0/', 'http://100.64.0.1/',
                    'http://224.0.0.1/', 'http://240.0.0.1/', 'http://[::1]/', 'http://[fe80::1]/',
                    'http://[fc00::1]/', 'http://[::ffff:127.0.0.1]/', 'http://[::ffff:169.254.169.254]/',
                    'http://[2002:7f00:1::]/', 'http://[fd00:ec2::254]/']:
            with self.assertRaises(OutboundBlocked, msg=url):
                validate_url(url)

    def test_noncanonical_ip_forms_rejected(self):
        for url in ['http://2130706433/', 'http://0x7f000001/', 'http://0x7f.0.0.1/', 'http://127.1/',
                    'http://0177.0.0.1/', 'http://017700000001/', 'http://1.2.3.4.5/']:
            with self.assertRaises(OutboundBlocked, msg=url):
                validate_url(url)

    def test_malformed_and_ambiguous_hosts(self):
        for url in ['http:///x', 'http://exa mple.com/', 'http://example.com\\@evil.com/', 'http://[::1/',
                    'http://::1/', 'http://[fe80::1%25eth0]/', 'http://-bad-.com/', 'http://a..b.com/', '',
                    'http://' + 'a' * 300 + '.com/']:
            with self.assertRaises(OutboundBlocked, msg=url):
                validate_url(url)

    def test_internal_hostnames_rejected_without_dns(self):
        for url in ['http://localhost/', 'http://db.internal/', 'http://metadata.google.internal/',
                    'http://printer.local/', 'http://intranet/']:
            with self.assertRaises(OutboundBlocked, msg=url):
                validate_url(url)

    def test_dns_to_private_or_metadata_rejected(self):
        for host in ['internal.example.net', 'meta.example.net', 'loop6.example.org', 'mapped.example.org']:
            with self.assertRaises(OutboundBlocked, msg=host):
                validate_url(f'http://{host}/')

    def test_mixed_dns_answers_fail_closed(self):
        with self.assertRaises(OutboundBlocked):
            validate_url('http://mixed.example.net/')

    def test_public_ipv6_allowed(self):
        self.assertEqual(validate_url('http://v6.example.org/').addresses[0], '2606:2800:220:1:248:1893:25c8:1946')

    def test_dns_failure_fails_closed(self):
        with self.assertRaises(OutboundError):
            validate_url('http://nonexistent.example.com/')

    def test_check_url_helper(self):
        self.assertEqual(outbound.check_url('http://10.0.0.1/'), (False, 'non_public_destination'))


class PinnedTransportTests(OutboundBase):
    def test_connection_pinned_to_validated_ip_with_hostname_header(self):
        log = []
        resp = safe_request('https://www.example.com/x', pool_factory=_FakePool([_FakeResp()], log))
        self.assertEqual(log, [('www.example.com', '93.184.216.34')])
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.peer_ip, '93.184.216.34')

    def test_dns_rebinding_cannot_redirect_connection(self):
        """Resolver changes its answer after validation: the pinned IP is still used for that hop."""
        answers = iter([['93.184.216.34'], ['127.0.0.1']])
        outbound.set_resolver(lambda host, port: next(answers))
        log = []
        safe_request('http://www.example.com/', pool_factory=_FakePool([_FakeResp()], log))
        self.assertEqual(log[0][1], '93.184.216.34')

    def test_redirect_to_private_destination_blocked(self):
        log = []
        script = [_FakeResp(302, {'Location': 'http://169.254.169.254/latest/'})]
        with self.assertRaises(OutboundBlocked):
            safe_request('http://www.example.com/', pool_factory=_FakePool(script, log))
        self.assertEqual(len(log), 1)  # never connected to the redirect target

    def test_redirect_to_rebinding_host_blocked(self):
        script = [_FakeResp(301, {'Location': 'http://internal.example.net/admin'})]
        with self.assertRaises(OutboundBlocked):
            safe_request('http://www.example.com/', pool_factory=_FakePool(script, []))

    def test_redirect_to_unsafe_scheme_blocked(self):
        script = [_FakeResp(302, {'Location': 'file:///etc/passwd'})]
        with self.assertRaises(OutboundBlocked):
            safe_request('http://www.example.com/', pool_factory=_FakePool(script, []))

    def test_each_redirect_validated_and_limited(self):
        log = []
        script = [_FakeResp(302, {'Location': 'https://cdn.example.com/a'}),
                  _FakeResp(302, {'Location': '/b'}), _FakeResp(200)]
        resp = safe_request('http://www.example.com/', pool_factory=_FakePool(script, log))
        self.assertEqual([ip for _, ip in log], ['93.184.216.34', '93.184.216.36', '93.184.216.36'])
        self.assertEqual(resp.url, 'https://cdn.example.com/b')
        self.assertEqual(len(resp.history), 3)
        loop = [_FakeResp(302, {'Location': 'http://www.example.com/'}) for _ in range(5)]
        with self.assertRaises(OutboundBlocked) as ctx:
            safe_request('http://www.example.com/', max_redirects=3, pool_factory=_FakePool(loop, []))
        self.assertEqual(ctx.exception.reason, 'too_many_redirects')

    def test_response_size_cap(self):
        resp = safe_request('http://www.example.com/', max_bytes=10,
                            pool_factory=_FakePool([_FakeResp(body=b'x' * 100)], []))
        self.assertTrue(resp.truncated)
        self.assertEqual(len(resp.body), 10)

    def test_only_get_and_head(self):
        with self.assertRaises(OutboundBlocked):
            safe_request('http://www.example.com/', method='POST')

    def test_tls_inspection_respects_policy(self):
        with self.assertRaises(OutboundBlocked):
            outbound.inspect_tls('https://internal.example.net/')
        with mock.patch('User.security.outbound.socket.create_connection',
                        side_effect=ConnectionRefusedError()) as conn:
            result = outbound.inspect_tls('http://www.example.com/')
        self.assertEqual(conn.call_args[0][0], ('93.184.216.34', 443))
        self.assertIsNone(result['verified'])  # unknown, NOT "invalid certificate"


class CollectorPolicyTests(OutboundBase):
    def test_webpage_analyzer_blocks_private_target(self):
        from User.services.nikhil.webpage_analyzer import WebpageAnalyzer
        evidence = WebpageAnalyzer.analyze_webpage('http://192.168.1.1/admin')
        self.assertEqual(evidence['status'], 'BLOCKED')
        self.assertEqual(evidence['security_block'], 'non_public_destination')

    def test_webpage_analyzer_redacts_target_cookies(self):
        from User.services.nikhil.webpage_analyzer import WebpageAnalyzer
        fake = outbound.SafeResponse(url='http://www.example.com/', status=200,
                                     headers={'Content-Type': 'text/html', 'Set-Cookie': 'sid=SECRET'},
                                     body=b'<html><body><form><input type="password"></form></body></html>')
        with mock.patch('User.security.outbound.safe_request', return_value=fake):
            evidence = WebpageAnalyzer.analyze_webpage('http://www.example.com/')
        self.assertEqual(evidence['status'], 'SUCCESS')
        self.assertIn('PASSWORD_FORM', evidence['indicators'])
        self.assertNotIn('SECRET', str(evidence['response_headers']))

    def test_network_analyzer_blocks_private_target(self):
        from User.services.nikhil.network_analyzer import NetworkAnalyzer
        evidence = NetworkAnalyzer.analyze_network('http://internal.example.net/')
        self.assertEqual(evidence['status'], 'BLOCKED')
        self.assertIsNone(evidence['ip_resolution']['primary_ip'])

    def test_blocked_evidence_never_yields_benign(self):
        from User.services.nikhil.final_classifier import FinalClassifier
        result = FinalClassifier.classify('Benign', 0.7, {
            'webpage': {'status': 'BLOCKED', 'indicators': []},
            'network': {'status': 'BLOCKED'},
            'threat_intelligence': {'status': 'UNAVAILABLE', 'trusted_domain': {'is_known': True}},
        })
        self.assertNotEqual(result['final_classification'], 'Benign')


class _Route:
    def __init__(self):
        self.action = None

    def abort(self, code='failed'):
        self.action = ('abort', code)

    def fulfill(self, **kwargs):
        self.action = ('fulfill', kwargs)


class _Request:
    def __init__(self, url, method='GET', resource_type='document'):
        self.url, self.method, self.resource_type, self.headers = url, method, resource_type, {}


@override_settings(VISUAL_ANALYSIS_ENABLED=True)
class BrowserEgressTests(OutboundBase):
    """The browser never connects itself: every request is policy-checked and fulfilled by the pinned transport."""

    def _run(self, url, requests):
        outcomes = []
        captured = {}
        page = mock.MagicMock()
        page.title.return_value = 'Fixture'

        def goto(target, wait_until):
            for req in requests:
                route = _Route()
                captured['handler'](route, req)
                outcomes.append((req.url, req.method, route.action[0]))

        def screenshot(path, full_page):
            with open(path, 'wb') as fh:
                fh.write(b'\x89PNG fixture')

        page.goto.side_effect = goto
        page.screenshot.side_effect = screenshot
        context = mock.MagicMock()
        context.route.side_effect = lambda pattern, handler: captured.__setitem__('handler', handler)
        context.new_page.return_value = page
        browser = mock.MagicMock()
        browser.new_context.return_value = context
        pw = mock.MagicMock()
        pw.chromium.launch.return_value = browser
        manager = mock.MagicMock()
        manager.__enter__.return_value = pw

        real_validate = outbound.validate_url

        def fake_fetch(u, method='GET', **kw):
            real_validate(u)  # real policy check on every sub-request
            return outbound.SafeResponse(url=u, status=200, headers={'Content-Type': 'text/html'}, body=b'ok')

        from User.services.nikhil.visual_analyzer import VisualAnalyzer
        with mock.patch('playwright.sync_api.sync_playwright', return_value=manager), \
                mock.patch('User.security.outbound.safe_request', side_effect=fake_fetch):
            evidence = VisualAnalyzer.analyze_visual(url, scan_id=1, tenant_id='user:1',
                                                     investigation_id='0123456789abcdef0123456789abcdef')
        return evidence, outcomes, pw, browser

    def test_subrequests_policy_enforced(self):
        evidence, outcomes, pw, browser = self._run('http://www.example.com/', [
            _Request('http://www.example.com/'),
            _Request('http://cdn.example.com/app.css', resource_type='stylesheet'),
            _Request('http://169.254.169.254/latest/meta-data/', resource_type='image'),
            _Request('http://internal.example.net/x', resource_type='script'),
            _Request('http://www.example.com/form', method='POST'),
            _Request('ws://www.example.com/socket', resource_type='websocket'),
        ])
        actions = {(u, m): a for u, m, a in outcomes}
        self.assertEqual(actions[('http://www.example.com/', 'GET')], 'fulfill')
        self.assertEqual(actions[('http://cdn.example.com/app.css', 'GET')], 'fulfill')
        self.assertEqual(actions[('http://169.254.169.254/latest/meta-data/', 'GET')], 'abort')
        self.assertEqual(actions[('http://internal.example.net/x', 'GET')], 'abort')
        self.assertEqual(actions[('http://www.example.com/form', 'POST')], 'abort')
        self.assertEqual(actions[('ws://www.example.com/socket', 'GET')], 'abort')
        self.assertEqual(evidence['status'], 'SUCCESS')
        self.assertEqual(evidence['screenshot_reference'], '/media/screenshots/0123456789abcdef0123456789abcdef.png')
        launch_kwargs = pw.chromium.launch.call_args.kwargs
        self.assertEqual(launch_kwargs['proxy']['server'], 'http://127.0.0.1:9')
        ctx_kwargs = browser.new_context.call_args.kwargs
        self.assertFalse(ctx_kwargs['java_script_enabled'])
        self.assertFalse(ctx_kwargs['ignore_https_errors'])
        self.assertFalse(ctx_kwargs['accept_downloads'])
        self.assertEqual(ctx_kwargs['service_workers'], 'block')

    def test_blocked_top_level_never_launches_browser(self):
        evidence, outcomes, pw, _ = self._run('http://10.0.0.1/', [])
        self.assertEqual(evidence['status'], 'BLOCKED')
        pw.chromium.launch.assert_not_called()

    @override_settings(VISUAL_ANALYSIS_ENABLED=False)
    def test_visual_analysis_can_be_disabled(self):
        from User.services.nikhil.visual_analyzer import VisualAnalyzer
        evidence = VisualAnalyzer.analyze_visual('http://www.example.com/', tenant_id='user:1',
                                                 investigation_id='0123456789abcdef0123456789abcdef')
        self.assertEqual(evidence['status'], 'UNAVAILABLE')

    def test_missing_tenant_identity_refused(self):
        from User.services.nikhil.visual_analyzer import VisualAnalyzer
        with mock.patch('playwright.sync_api.sync_playwright'):
            evidence = VisualAnalyzer.analyze_visual('http://www.example.com/', scan_id=1)
        self.assertEqual(evidence['status'], 'UNAVAILABLE')
