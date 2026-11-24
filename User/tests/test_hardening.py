"""Task 6/7: hardening, redaction, password policy, admin dashboard, destructive-script guards, PARI regression."""

import json
import logging
import os
import subprocess
import sys
from unittest import mock

from django.conf import settings
from django.contrib.auth.models import User
from django.test import SimpleTestCase

from User.models import MaliciousBot
from User.security.redaction import REDACTED, RedactingFilter, redact_document, redact_headers, redact_text

from .helpers import TenantTestCase

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class RedactionTests(SimpleTestCase):
    def test_text_redaction(self):
        samples = [
            'GET /v1beta/models/x:generateContent?key=AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ012345 failed',
            'Authorization: Bearer abcdefghijklmnop12345',
            'mongodb+srv://admin:hunter2pass@cluster0.example.net/db',
            'Auth-Key: 0123456789abcdef0123',
        ]
        for text in samples:
            out = redact_text(text)
            self.assertIn(REDACTED, out, text)
        self.assertNotIn('hunter2pass', redact_text(samples[2]))
        with mock.patch.dict(os.environ, {'MYSQL_PASSWORD': 'Sup3r-Secret-Value'}):
            self.assertNotIn('Sup3r-Secret-Value', redact_text('connect failed with Sup3r-Secret-Value'))

    def test_header_and_document_redaction(self):
        headers = redact_headers({'Set-Cookie': 'a=b', 'Authorization': 'x', 'Content-Type': 'text/html'})
        self.assertEqual(headers['Set-Cookie'], REDACTED)
        self.assertEqual(headers['Authorization'], REDACTED)
        self.assertEqual(headers['Content-Type'], 'text/html')
        doc = redact_document({'a': [{'response_headers': {'cookie': 'sid=1'}}], 'b': 'token=abcdefgh123 x'})
        self.assertEqual(doc['a'][0]['response_headers']['cookie'], REDACTED)
        self.assertNotIn('abcdefgh123', doc['b'])

    def test_logging_filter(self):
        record = logging.LogRecord('x', logging.ERROR, __file__, 1, 'failed %s', ('?key=AIzaSyABCDEFGHIJKLMNOPQRSTUVWX12',),
                                   None)
        RedactingFilter().filter(record)
        self.assertNotIn('AIzaSy', record.getMessage())


class GeminiKeyTransportTests(SimpleTestCase):
    def test_key_sent_in_header_not_url(self):
        from User.services.nikhil.gemini_provider import GeminiProvider
        with mock.patch.dict(os.environ, {'GEMINI_API_KEY': 'AIzaSyTESTKEY00000000000000000000000', 'GEMINI_ENABLED': 'true'}):
            provider = GeminiProvider()
        response = mock.MagicMock(status_code=200)
        response.json.return_value = {'candidates': [{'content': {'parts': [{'text': json.dumps(
            {'assessment': 'INCONCLUSIVE', 'confidence': 0.5})}]}}]}
        with mock.patch('requests.post', return_value=response) as post:
            result = provider.analyze({'x': 1})
        self.assertEqual(result['status'], 'SUCCESS')
        args, kwargs = post.call_args
        self.assertNotIn('key=', args[0])
        self.assertNotIn('params', kwargs)
        self.assertEqual(kwargs['headers']['x-goog-api-key'], 'AIzaSyTESTKEY00000000000000000000000')

    def test_provider_errors_are_redacted(self):
        from User.services.nikhil.gemini_provider import GeminiProvider
        with mock.patch.dict(os.environ, {'GEMINI_API_KEY': 'AIzaSyTESTKEY00000000000000000000000'}):
            provider = GeminiProvider()
            with mock.patch('requests.post', side_effect=RuntimeError(
                    'HTTPSConnectionPool(...) url: /v1beta?key=AIzaSyTESTKEY00000000000000000000000')):
                result = provider.analyze({'x': 1})
        self.assertNotIn('AIzaSyTESTKEY', json.dumps(result))


class SettingsHardeningTests(SimpleTestCase):
    def _settings_import(self, env):
        code = 'import MaliciousBot.settings as s; print("OK", s.SESSION_COOKIE_SECURE, s.SECURE_SSL_REDIRECT, s.SECURE_HSTS_SECONDS)'
        clean = {k: v for k, v in os.environ.items() if k not in ('SECRET_KEY', 'RENDER', 'PRODUCTION', 'DEBUG')}
        clean.update(env)
        return subprocess.run([sys.executable, '-c', code], cwd=REPO_ROOT, env=clean, capture_output=True, text=True,
                              timeout=120)

    def test_production_requires_strong_secret_key(self):
        result = self._settings_import({'RENDER': '1'})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('SECRET_KEY', result.stderr)
        weak = self._settings_import({'RENDER': '1', 'SECRET_KEY': 'change-me-in-env'})
        self.assertNotEqual(weak.returncode, 0)

    def test_production_security_defaults(self):
        result = self._settings_import({'RENDER': '1', 'SECRET_KEY': 'x' * 50})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('OK True True 86400', result.stdout)

    def test_local_development_still_works(self):
        result = self._settings_import({})
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_static_settings(self):
        self.assertEqual(settings.X_FRAME_OPTIONS, 'DENY')
        self.assertTrue(settings.SECURE_CONTENT_TYPE_NOSNIFF)
        self.assertEqual(settings.SESSION_COOKIE_SAMESITE, 'Lax')
        self.assertIn(r'^health$', settings.SECURE_REDIRECT_EXEMPT)
        self.assertIn('User.security.headers.SecurityHeadersMiddleware', settings.MIDDLEWARE)

    def test_env_example_has_no_secrets_and_is_not_ignored(self):
        with open(os.path.join(REPO_ROOT, '.env.example'), encoding='utf-8') as fh:
            content = fh.read()
        for name in ('GEMINI_API_KEY', 'MYSQL_PASSWORD', 'MONGODB_URI', 'FALLBACK_SERVICE_TOKEN'):
            self.assertRegex(content, rf'(?m)^{name}=$')
        result = subprocess.run(['git', 'check-ignore', '-q', '.env.example'], cwd=REPO_ROOT)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(subprocess.run(['git', 'check-ignore', '-q', '.env'], cwd=REPO_ROOT).returncode, 0)


class WebHardeningTests(TenantTestCase):
    def test_security_headers(self):
        response = self.client.get('/')
        self.assertIn("frame-ancestors 'none'", response['Content-Security-Policy'])
        self.assertEqual(response['X-Frame-Options'], 'DENY')
        self.assertEqual(response['X-Content-Type-Options'], 'nosniff')
        self.assertIn('camera=()', response['Permissions-Policy'])

    def test_registration_password_validation(self):
        response = self.client.post('/register', {'username': 'carol', 'email': 'carol@example.test',
                                                  'password': 'password123', 'password2': 'password123'})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(User.objects.filter(username='carol').exists())

    def test_registration_input_validation_and_generic_duplicate_message(self):
        bad = self.client.post('/register', {'username': 'bad user!', 'email': 'x@example.test',
                                             'password': self.password, 'password2': self.password})
        self.assertFalse(User.objects.filter(email='x@example.test').exists())
        self.assertEqual(bad.status_code, 200)
        dup_user = self.client.post('/register', {'username': 'ALICE', 'email': 'new@example.test',
                                                  'password': self.password, 'password2': self.password})
        dup_mail = self.client.post('/register', {'username': 'newname', 'email': 'alice@example.test',
                                                  'password': self.password, 'password2': self.password})
        msg = lambda r: [str(m) for m in r.context['messages']]
        self.assertEqual(msg(dup_user), msg(dup_mail))

    def test_login_failure_messages_do_not_disclose_accounts(self):
        unknown = self.client.post('/login', {'username': 'nobody', 'password': 'x'})
        wrong = self.client.post('/login', {'username': 'alice', 'password': 'x'})
        msg = lambda r: [str(m) for m in r.context['messages']]
        self.assertEqual(msg(unknown), msg(wrong))
        nonadmin = self.client.post('/adminlogin', {'username': 'alice', 'password': self.password})
        self.assertNotIn('not an admin', nonadmin.content.decode())

    def test_status_endpoint_minimal_for_anonymous(self):
        payload = self.client.get('/status').json()
        self.assertEqual(set(payload), {'status', 'timestamp', 'database'})


class AdminDashboardTests(TenantTestCase):
    def setUp(self):
        super().setUp()
        from User.models import UserDatabaseRegistry
        UserDatabaseRegistry.objects.using('default').create(user_id=1, username='alice', database_name='db1')
        UserDatabaseRegistry.objects.using('default').create(user_id=2, username='bob', database_name='db2')
        MaliciousBot.objects.using('user_1').create(user=self.alice, url='https://a.example.com', prediction_type='Benign')
        MaliciousBot.objects.using('user_2').create(user=self.bob, url='https://b.example.com', prediction_type='Phishing')
        self.admin = User.objects.create_superuser(id=3, username='root', email='r@example.test', password=self.password)
        patcher = mock.patch('User.db_manager.register_database_connection')
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_superuser_sees_rows_from_all_tenants(self):
        self.client.force_login(self.admin)
        response = self.client.get('/adminhome')
        self.assertEqual(response.status_code, 200)
        self.assertEqual({row['url'] for row in response.context['data']},
                         {'https://a.example.com', 'https://b.example.com'})
        self.assertContains(response, 'https://b.example.com')

    def test_non_admin_redirected(self):
        self.client.force_login(self.alice)
        self.assertEqual(self.client.get('/adminhome').status_code, 302)


class DestructiveScriptGuardTests(SimpleTestCase):
    def setUp(self):
        sys.path.insert(0, REPO_ROOT)
        import importlib
        self.mod = importlib.import_module('migrate_sqlite_to_mysql')

    def test_dry_run_default_and_wildcards_rejected(self):
        args = self.mod.parse_args([])
        self.assertFalse(self.mod.assert_execution_allowed(args, environ={}))
        for bad in ['maliciousbot_%', 'maliciousbot_*', 'mysql', 'maliciousbot_core; DROP']:
            with self.assertRaises(self.mod.MigrationSafetyError):
                self.mod.validate_drop_allowlist([bad])

    def test_only_exact_allowlisted_names_dropped(self):
        existing = ['maliciousbot_core', 'maliciousbot_guest', 'maliciousbot_user_000001', 'mysql']
        self.assertEqual(self.mod.plan_database_drops(existing, ['maliciousbot_guest']), ['maliciousbot_guest'])
        self.assertEqual(self.mod.plan_database_drops(existing, []), [])

    def test_execute_requires_backup_confirmation_and_phrase(self):
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            backup = fh.name
        try:
            no_backup = self.mod.parse_args(['--execute'])
            with self.assertRaises(self.mod.MigrationSafetyError):
                self.mod.assert_execution_allowed(no_backup, environ={})
            no_phrase = self.mod.parse_args(['--execute', '--backup-confirmed', '--backup-path', backup,
                                             '--drop-database', 'maliciousbot_guest'])
            with self.assertRaises(self.mod.MigrationSafetyError):
                self.mod.assert_execution_allowed(no_phrase, environ={})
            ok = self.mod.parse_args(['--execute', '--backup-confirmed', '--backup-path', backup,
                                      '--drop-database', 'maliciousbot_guest', '--confirm', 'MIGRATE-AND-DROP'])
            self.assertTrue(self.mod.assert_execution_allowed(ok, environ={}))
            with self.assertRaises(self.mod.MigrationSafetyError):
                self.mod.assert_execution_allowed(ok, environ={'RENDER': '1'})
        finally:
            os.remove(backup)


class PariRegressionTests(SimpleTestCase):
    """AIML behaviour preserved: features, threshold semantics, classifier rules."""

    def test_feature_vector_unchanged(self):
        from User.services.ml_service import MLPredictionService
        with mock.patch('User.views.tld_extract') as ext:
            ext.return_value = mock.MagicMock(domain='google')
            feats = MLPredictionService.extract_pari_features('https://www.google.com')
        self.assertEqual([feats[n] for n in MLPredictionService.PARI_FEATURE_NAMES],
                         [10, 17, 0, 5, 0, 1, 1, 0, 32604616, 83981562])

    def test_threshold_default_and_inclusive(self):
        from User import services
        self.assertEqual(services.CONFIDENCE_THRESHOLD, float(os.environ.get('PARI_CONFIDENCE_THRESHOLD', '0.75')))
        self.assertTrue(0.75 >= services.get_confidence_threshold())

    def test_final_classifier_rules_unchanged(self):
        from User.services.nikhil.final_classifier import FinalClassifier
        base = {
            'webpage': {'status': 'SUCCESS', 'indicators': ['PASSWORD_FORM', 'CREDENTIAL_HARVESTING_TEXT'],
                        'page_structure': {'num_tags': 50}},
            'network': {'status': 'SUCCESS', 'ssl': {'verified': True}, 'http_metadata': {'redirect_chain': []},
                        'ip_resolution': {'primary_ip': '93.184.216.34'}},
            'threat_intelligence': {'status': 'SUCCESS', 'url_features': {'suspicious_token_count': 0, 'url_length': 30}},
        }
        result = FinalClassifier.classify('Benign', 0.6, base)
        self.assertEqual((result['final_classification'], result['risk_score']), ('Phishing', 0.88))
        base['webpage']['indicators'] = []
        self.assertEqual(FinalClassifier.classify('Phishing', 0.6, base)['final_classification'], 'Benign')

    def test_unverifiable_tls_is_not_scored_as_invalid(self):
        from User.services.nikhil.final_classifier import FinalClassifier
        result = FinalClassifier.classify('Benign', 0.6, {
            'network': {'status': 'SUCCESS', 'ssl': {'verified': None, 'error': 'port 443 connection refused'},
                        'http_metadata': {}, 'ip_resolution': {'primary_ip': '93.184.216.34'}}})
        self.assertEqual(result['corroboration']['all_scores']['Phishing'], 0.0)

    def test_logistic_regression_fallback_still_present(self):
        import inspect
        from User import views
        self.assertIn('LogisticRegression(', inspect.getsource(views._do_train_model))
