"""
Deployment-focused tests.

These tests cover the Render / Aiven MySQL wiring without requiring real
credentials, a live MySQL server, or any external API keys.

Run with:
    python manage.py test User
"""

import contextlib
import os
import ssl
import tempfile
from unittest import mock

from django.conf import settings
from django.db import connections
from django.test import SimpleTestCase

from MaliciousBot.db_config import (
    MySQLSSLConfigurationError,
    get_mysql_ssl_options,
    resolve_mysql_ssl_mode,
)

AIVEN_HOST = 'mysql-34f237c6-raptorparik2006-c4fd.k.aivencloud.com'


@contextlib.contextmanager
def stubbed_connection_cursor(fetchone_value=(1,)):
    """
    Temporarily replace the core-database cursor.

    Django's ``SimpleTestCase`` installs ``_DatabaseFailure`` wrappers as instance
    attributes on each connection in ``setUpClass`` and unwraps them in
    ``tearDownClass``. ``mock.patch`` cannot be used here because it deletes the
    instance attribute on exit instead of restoring it, which breaks teardown.
    This helper saves and restores the exact original object.
    """
    connection = connections['default']
    had_instance_attr = 'cursor' in connection.__dict__
    original = connection.__dict__.get('cursor')

    inner = mock.MagicMock()
    inner.fetchone.return_value = fetchone_value
    inner.execute.return_value = None

    cursor = mock.MagicMock()
    cursor.return_value.__enter__.return_value = inner
    connection.cursor = cursor
    try:
        yield inner
    finally:
        if had_instance_attr:
            connection.cursor = original
        else:
            del connection.cursor


def _env_without(*names):
    """Context manager that removes the named environment variables."""
    return _EnvWithout(names)


class _EnvWithout:
    """Remove specific environment variables for the duration of a block."""

    def __init__(self, names):
        self.names = names
        self._saved = {}

    def __enter__(self):
        for name in self.names:
            self._saved[name] = os.environ.pop(name, None)
        return self

    def __exit__(self, *exc_info):
        for name, value in self._saved.items():
            if value is not None:
                os.environ[name] = value
            else:
                os.environ.pop(name, None)
        return False


def _self_signed_ca_pem():
    """Generate a throwaway self-signed CA certificate for TLS context tests.

    Generated at runtime purely for testing. It is not a secret and is never
    written into the repository.
    """
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, 'MaliciousBot Test CA')]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.PEM).decode('utf-8')


class SslModeResolutionTests(SimpleTestCase):
    """MYSQL_SSL_MODE selection."""

    def test_local_development_defaults_to_no_ssl(self):
        with _env_without('MYSQL_SSL_MODE', 'MYSQL_SSL_CA'), mock.patch.dict(
            os.environ, {'MYSQL_HOST': 'localhost'}, clear=False
        ):
            self.assertEqual(resolve_mysql_ssl_mode(), 'DISABLED')
            self.assertEqual(get_mysql_ssl_options(), {})

    def test_remote_host_without_ca_defaults_to_required(self):
        with _env_without('MYSQL_SSL_MODE', 'MYSQL_SSL_CA'), mock.patch.dict(
            os.environ, {'MYSQL_HOST': AIVEN_HOST}, clear=False
        ):
            self.assertEqual(resolve_mysql_ssl_mode(), 'REQUIRED')

    def test_remote_host_with_ca_defaults_to_verify_ca(self):
        with _env_without('MYSQL_SSL_MODE'), mock.patch.dict(
            os.environ, {'MYSQL_HOST': AIVEN_HOST, 'MYSQL_SSL_CA': _self_signed_ca_pem()},
            clear=False,
        ):
            self.assertEqual(resolve_mysql_ssl_mode(), 'VERIFY_CA')

    def test_explicit_mode_is_honoured(self):
        pem = _self_signed_ca_pem()
        for mode in ('DISABLED', 'REQUIRED', 'VERIFY_CA', 'VERIFY_IDENTITY'):
            with self.subTest(mode=mode), mock.patch.dict(
                os.environ,
                {
                    'MYSQL_HOST': AIVEN_HOST,
                    'MYSQL_SSL_MODE': mode.lower(),
                    'MYSQL_SSL_CA': pem,
                },
                clear=False,
            ):
                self.assertEqual(resolve_mysql_ssl_mode(), mode)

    def test_invalid_mode_fails_fast(self):
        with mock.patch.dict(
            os.environ, {'MYSQL_HOST': AIVEN_HOST, 'MYSQL_SSL_MODE': 'VERIFY_EVERYTHING'},
            clear=False,
        ):
            with self.assertRaises(MySQLSSLConfigurationError):
                resolve_mysql_ssl_mode()

    def test_verifying_mode_without_ca_fails_fast(self):
        with mock.patch.dict(
            os.environ,
            {'MYSQL_HOST': AIVEN_HOST, 'MYSQL_SSL_MODE': 'VERIFY_CA'},
            clear=False,
        ), _env_without('MYSQL_SSL_CA'):
            with self.assertRaises(MySQLSSLConfigurationError):
                get_mysql_ssl_options()


class SslContextTests(SimpleTestCase):
    """The generated ssl.SSLContext is correct for each mode."""

    def test_required_mode_encrypts_without_verifying(self):
        with mock.patch.dict(
            os.environ,
            {'MYSQL_HOST': AIVEN_HOST, 'MYSQL_SSL_MODE': 'REQUIRED'},
            clear=False,
        ), _env_without('MYSQL_SSL_CA'):
            options = get_mysql_ssl_options()
        context = options['ssl']
        self.assertIsInstance(context, ssl.SSLContext)
        self.assertEqual(context.verify_mode, ssl.CERT_NONE)
        self.assertFalse(context.check_hostname)

    def test_verify_ca_checks_chain_but_not_hostname(self):
        with mock.patch.dict(
            os.environ,
            {'MYSQL_HOST': AIVEN_HOST, 'MYSQL_SSL_MODE': 'VERIFY_CA',
             'MYSQL_SSL_CA': _self_signed_ca_pem()},
            clear=False,
        ):
            context = get_mysql_ssl_options()['ssl']
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertFalse(context.check_hostname)

    def test_verify_identity_checks_chain_and_hostname(self):
        with mock.patch.dict(
            os.environ,
            {'MYSQL_HOST': AIVEN_HOST, 'MYSQL_SSL_MODE': 'VERIFY_IDENTITY',
             'MYSQL_SSL_CA': _self_signed_ca_pem()},
            clear=False,
        ):
            context = get_mysql_ssl_options()['ssl']
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)

    def test_ca_may_be_supplied_as_a_file_path(self):
        with tempfile.NamedTemporaryFile('w', suffix='.pem', delete=False) as handle:
            handle.write(_self_signed_ca_pem())
            ca_path = handle.name
        try:
            with mock.patch.dict(
                os.environ,
                {'MYSQL_HOST': AIVEN_HOST, 'MYSQL_SSL_MODE': 'VERIFY_CA',
                 'MYSQL_SSL_CA': ca_path},
                clear=False,
            ):
                context = get_mysql_ssl_options()['ssl']
            self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        finally:
            os.unlink(ca_path)

    def test_missing_ca_file_fails_fast(self):
        with mock.patch.dict(
            os.environ,
            {'MYSQL_HOST': AIVEN_HOST, 'MYSQL_SSL_MODE': 'VERIFY_CA',
             'MYSQL_SSL_CA': '/nonexistent/aiven-ca.pem'},
            clear=False,
        ):
            with self.assertRaises(MySQLSSLConfigurationError):
                get_mysql_ssl_options()

    def test_tls_floor_is_tls_1_2(self):
        with mock.patch.dict(
            os.environ,
            {'MYSQL_HOST': AIVEN_HOST, 'MYSQL_SSL_MODE': 'REQUIRED'},
            clear=False,
        ), _env_without('MYSQL_SSL_CA'):
            context = get_mysql_ssl_options()['ssl']
        self.assertGreaterEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)

    def test_options_are_an_ssl_context_pyMySQL_accepts(self):
        """Django forwards OPTIONS straight to PyMySQL; confirm the kwarg works."""
        import pymysql

        with mock.patch.dict(
            os.environ,
            {'MYSQL_HOST': AIVEN_HOST, 'MYSQL_SSL_MODE': 'REQUIRED'},
            clear=False,
        ), _env_without('MYSQL_SSL_CA'):
            options = get_mysql_ssl_options()

        # An unroutable port makes the handshake fail fast; what matters is that
        # PyMySQL accepts the argument and attempts a TLS connection.
        with self.assertRaises(Exception) as caught:
            pymysql.connect(
                host=AIVEN_HOST, port=1, user='u', password='p', **options
            )
        self.assertNotIsInstance(caught.exception, (TypeError, KeyError))


class DatabaseConfigurationTests(SimpleTestCase):
    """default / guest_db / per-user databases must be configured identically."""

    def test_core_and_guest_share_connection_settings(self):
        default = settings.DATABASES['default']
        guest = settings.DATABASES['guest_db']

        for key in ('ENGINE', 'HOST', 'PORT', 'USER', 'PASSWORD'):
            self.assertEqual(default[key], guest[key], f'mismatch on {key}')

        self.assertEqual(default['NAME'], 'maliciousbot_core')
        self.assertEqual(guest['NAME'], 'maliciousbot_guest')

    def test_charset_and_strict_sql_mode_preserved(self):
        for alias in ('default', 'guest_db'):
            options = settings.DATABASES[alias]['OPTIONS']
            self.assertEqual(options['charset'], 'utf8mb4')
            self.assertEqual(
                options['init_command'], "SET sql_mode='STRICT_TRANS_TABLES'"
            )

    def test_dynamic_user_database_inherits_full_configuration(self):
        from User.db_manager import get_mysql_db_config

        default = settings.DATABASES['default']
        generated = get_mysql_db_config('maliciousbot_user_000123')

        self.assertEqual(generated['NAME'], 'maliciousbot_user_000123')
        for key in ('ENGINE', 'HOST', 'PORT', 'USER', 'PASSWORD'):
            self.assertEqual(default[key], generated[key], f'mismatch on {key}')
        self.assertEqual(default['OPTIONS']['charset'], generated['OPTIONS']['charset'])
        self.assertEqual(
            default['OPTIONS']['init_command'], generated['OPTIONS']['init_command']
        )
        # The SSL entry (when present) must be present in both, identically.
        self.assertEqual(
            default['OPTIONS'].get('ssl') is not None,
            generated['OPTIONS'].get('ssl') is not None,
        )

    def test_user_database_naming_is_stable_and_safe(self):
        from User.db_manager import get_user_db_name

        self.assertEqual(get_user_db_name(1), 'maliciousbot_user_000001')
        self.assertEqual(get_user_db_name(42), 'maliciousbot_user_000042')

    def test_server_and_admin_config_use_aiven_credentials(self):
        from User.db_manager import get_mysql_admin_config, get_mysql_server_config

        with mock.patch.dict(
            os.environ,
            {
                'MYSQL_HOST': AIVEN_HOST,
                'MYSQL_PORT': '26143',
                'MYSQL_USER': 'test-admin-user',
                'MYSQL_PASSWORD': 'test-admin-pass',
                'MYSQL_ADMIN_USER': 'test-admin-user',
                'MYSQL_ADMIN_PASSWORD': 'test-admin-pass',
            },
            clear=False,
        ):
            server = get_mysql_server_config()
            admin = get_mysql_admin_config()

        self.assertEqual(server['HOST'], AIVEN_HOST)
        self.assertEqual(server['PORT'], 26143)
        self.assertEqual(admin['HOST'], AIVEN_HOST)
        self.assertEqual(admin['PORT'], 26143)
        self.assertEqual(admin['USER'], server['USER'])
        self.assertEqual(admin['PASSWORD'], server['PASSWORD'])

    def test_database_provisioning_rejects_unsafe_names(self):
        from User.db_manager import ensure_mysql_database_exists

        for bad_name in ('drop-db', 'a`b', 'db;DROP', 'db name', ''):
            with self.subTest(name=bad_name):
                with self.assertRaises(ValueError):
                    ensure_mysql_database_exists(bad_name)

    def test_provisioning_connection_receives_aiven_ssl(self):
        """ensure_mysql_database_exists must not connect over a plaintext socket."""
        import pymysql

        from User import db_manager

        recorded = {}

        class _Cursor:
            def execute(self, sql, *args, **kwargs):
                recorded.setdefault('sql', []).append(sql)

            def close(self):
                pass

        class _Connection:
            def cursor(self):
                return _Cursor()

            def commit(self):
                pass

            def close(self):
                pass

        def fake_connect(**kwargs):
            recorded['connect_kwargs'] = kwargs
            return _Connection()

        with mock.patch.dict(
            os.environ,
            {
                'MYSQL_HOST': AIVEN_HOST,
                'MYSQL_PORT': '26143',
                'MYSQL_ADMIN_USER': 'test-admin-user',
                'MYSQL_ADMIN_PASSWORD': 'test-admin-pass',
                'MYSQL_SSL_MODE': 'VERIFY_CA',
                'MYSQL_SSL_CA': _self_signed_ca_pem(),
            },
            clear=False,
        ), mock.patch.object(pymysql, 'connect', side_effect=fake_connect):
            with mock.patch.dict(
                __import__('sys').modules, {'MySQLdb': None}
            ):
                db_manager.ensure_mysql_database_exists('maliciousbot_user_000001')

        kwargs = recorded['connect_kwargs']
        self.assertEqual(kwargs['host'], AIVEN_HOST)
        self.assertEqual(kwargs['port'], 26143)
        self.assertEqual(kwargs['user'], 'test-admin-user')
        self.assertIsInstance(kwargs['ssl'], ssl.SSLContext)
        self.assertEqual(kwargs['ssl'].verify_mode, ssl.CERT_REQUIRED)

    def test_router_still_enforces_user_isolation(self):
        from User.db_router import UserDatabaseRouter

        router = UserDatabaseRouter()
        # Control tables stay in the core database.
        self.assertTrue(router.allow_migrate('default', 'auth', 'user'))
        self.assertTrue(
            router.allow_migrate('default', 'User', 'userdatabaseregistry')
        )
        # Application tables never migrate into the core database.
        self.assertFalse(router.allow_migrate('default', 'User', 'scan'))
        # Per-user and guest databases receive the application schema.
        self.assertTrue(router.allow_migrate('guest_db', 'User', 'scan'))
        self.assertTrue(router.allow_migrate('user_1', 'User', 'scan'))
        self.assertFalse(router.allow_migrate('user_1', 'auth', 'user'))


class SettingsBehaviourTests(SimpleTestCase):
    """Render-facing settings behave correctly."""

    def test_local_defaults_allow_localhost(self):
        from MaliciousBot.settings import build_allowed_hosts

        with _env_without('ALLOWED_HOSTS', 'RENDER_EXTERNAL_HOSTNAME'):
            self.assertEqual(
                build_allowed_hosts(), ['127.0.0.1', 'localhost', 'testserver']
            )

    def test_render_hostname_is_added_to_allowed_hosts(self):
        from MaliciousBot.settings import build_allowed_hosts, build_csrf_trusted_origins

        env = {'RENDER_EXTERNAL_HOSTNAME': 'dbms-el.onrender.com'}
        with mock.patch.dict(os.environ, env, clear=False), _env_without(
            'ALLOWED_HOSTS', 'CSRF_TRUSTED_ORIGINS'
        ):
            self.assertEqual(build_allowed_hosts(), ['dbms-el.onrender.com'])
            self.assertEqual(
                build_csrf_trusted_origins(), ['https://dbms-el.onrender.com']
            )

    def test_explicit_env_values_are_supported(self):
        from MaliciousBot.settings import build_allowed_hosts

        with mock.patch.dict(
            os.environ, {'ALLOWED_HOSTS': 'example.com, another.example.com'},
            clear=False,
        ), _env_without('RENDER_EXTERNAL_HOSTNAME'):
            self.assertEqual(
                build_allowed_hosts(), ['example.com', 'another.example.com']
            )

    def test_render_hostname_is_not_duplicated(self):
        from MaliciousBot.settings import build_allowed_hosts, build_csrf_trusted_origins

        env = {
            'RENDER_EXTERNAL_HOSTNAME': 'dbms-el.onrender.com',
            'ALLOWED_HOSTS': 'dbms-el.onrender.com,example.com',
            'CSRF_TRUSTED_ORIGINS': 'https://dbms-el.onrender.com',
        }
        with mock.patch.dict(os.environ, env, clear=False):
            hosts = build_allowed_hosts()
            origins = build_csrf_trusted_origins()

        self.assertEqual(hosts.count('dbms-el.onrender.com'), 1)
        self.assertEqual(hosts, ['dbms-el.onrender.com', 'example.com'])
        self.assertEqual(origins.count('https://dbms-el.onrender.com'), 1)

    def test_debug_defaults_to_false_on_render(self):
        from MaliciousBot.settings import resolve_debug

        with mock.patch.dict(os.environ, {'RENDER': '1'}, clear=False), _env_without(
            'DEBUG'
        ):
            self.assertFalse(resolve_debug())

    def test_debug_defaults_to_true_locally(self):
        from MaliciousBot.settings import resolve_debug

        with _env_without('DEBUG', 'RENDER', 'PRODUCTION'):
            self.assertTrue(resolve_debug())

    def test_debug_is_false_when_explicitly_disabled(self):
        from MaliciousBot.settings import resolve_debug

        with mock.patch.dict(os.environ, {'DEBUG': 'False'}, clear=False):
            self.assertFalse(resolve_debug())

    def test_static_and_whitenoise_configuration(self):
        self.assertTrue(settings.STATIC_ROOT.endswith('staticfiles'))
        self.assertEqual(
            settings.STORAGES['staticfiles']['BACKEND'],
            'whitenoise.storage.CompressedStaticFilesStorage',
        )
        self.assertIn(
            os.path.join(settings.BASE_DIR, 'static'), settings.STATICFILES_DIRS
        )
        self.assertIn(
            'whitenoise.middleware.WhiteNoiseMiddleware', settings.MIDDLEWARE
        )

    def test_wsgi_application_path(self):
        self.assertEqual(settings.WSGI_APPLICATION, 'MaliciousBot.wsgi.application')

    def test_database_router_is_configured(self):
        self.assertIn('User.db_router.UserDatabaseRouter', settings.DATABASE_ROUTERS)

    def test_proxy_ssl_header_set_for_render(self):
        self.assertEqual(
            settings.SECURE_PROXY_SSL_HEADER, ('HTTP_X_FORWARDED_PROTO', 'https')
        )


class HealthEndpointTests(SimpleTestCase):
    """/health and /status must work on Render without authentication."""

    def test_health_is_public_and_checks_the_core_database(self):
        import json

        with stubbed_connection_cursor():
            response = self.client.get('/health')

        self.assertEqual(response.status_code, 200)
        payload = json.loads(response.content)
        self.assertEqual(payload['status'], 'ok')
        self.assertEqual(payload['database'], 'django.db.backends.mysql')

    def test_health_reports_database_failure_without_crashing(self):
        import json

        with stubbed_connection_cursor() as inner:
            inner.execute.side_effect = Exception('boom')
            response = self.client.get('/health')

        self.assertEqual(response.status_code, 503)
        payload = json.loads(response.content)
        self.assertEqual(payload['status'], 'error')
        self.assertIn('boom', payload['message'])

    def test_health_does_not_provision_databases(self):
        """Render polls /health; it must not run CREATE DATABASE on every hit."""
        with mock.patch('User.middleware.ensure_user_database') as ensure:
            with stubbed_connection_cursor():
                self.client.get('/health')
        ensure.assert_not_called()

    def test_status_is_public_and_does_not_train_the_model(self):
        import json

        from django.contrib.auth.models import User as AuthUser

        from User import views
        from User.models import MaliciousBot

        with stubbed_connection_cursor(), \
                mock.patch.object(AuthUser.objects, 'count', return_value=3), \
                mock.patch.object(MaliciousBot.objects, 'count', return_value=7), \
                mock.patch.object(views, 'train_model') as train:
            response = self.client.get('/status')

        self.assertEqual(response.status_code, 200)
        payload = json.loads(response.content)
        self.assertEqual(payload['database']['status'], 'OK')
        self.assertEqual(payload['database']['users'], 3)
        self.assertEqual(payload['database']['predictions'], 7)
        train.assert_not_called()

    def test_status_degrades_when_database_is_unreachable(self):
        import json

        with stubbed_connection_cursor() as inner:
            inner.execute.side_effect = Exception('down')
            response = self.client.get('/status')

        self.assertEqual(response.status_code, 200)
        payload = json.loads(response.content)
        self.assertEqual(payload['status'], 'degraded')
        self.assertEqual(payload['database']['status'], 'ERROR')

    def test_health_and_status_do_not_require_login(self):
        from django.urls import reverse

        self.assertEqual(reverse('health'), '/health')
        self.assertEqual(reverse('status'), '/status')

    def test_middleware_routes_diagnostics_without_provisioning(self):
        """The middleware must skip DDL for /health and /status."""
        from User.middleware import NO_PROVISIONING_PATHS, UserDatabaseMiddleware

        self.assertIn('/health', NO_PROVISIONING_PATHS)
        self.assertIn('/status', NO_PROVISIONING_PATHS)
        self.assertIn('User.middleware.UserDatabaseMiddleware', settings.MIDDLEWARE)
        self.assertTrue(callable(UserDatabaseMiddleware))


class PyMySQLOnlyStartupTests(SimpleTestCase):
    """
    Render installs PyMySQL, not mysqlclient.

    This runs a subprocess with the mysqlclient C extension hidden from the
    import system, proving the bootstrap in ``MaliciousBot/__init__.py`` falls
    back to PyMySQL, that Django can construct its MySQL backend, and that the
    WSGI application object (what gunicorn imports) can be built.
    """

    BLOCK_AND_BOOT = r'''
import sys

# Hide mysqlclient so only PyMySQL can satisfy "import MySQLdb".
class _BlockMySQLdb:
    def find_module(self, fullname, path=None):
        return self.find_spec(fullname, path)

    def find_spec(self, fullname, path=None, target=None):
        if fullname == 'MySQLdb' or fullname.startswith('_mysql'):
            raise ImportError('MySQLdb blocked for this test')
        return None

sys.meta_path.insert(0, _BlockMySQLdb())

import os
sys.path.insert(0, r'%s')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'MaliciousBot.settings')

import django
django.setup()

import MySQLdb as Database
assert Database.__name__ == 'pymysql', Database.__name__

from django.db.backends.mysql.base import DatabaseWrapper  # noqa: F401
from django.db import connections
assert connections['default'].settings_dict['ENGINE'] == 'django.db.backends.mysql'

from MaliciousBot.wsgi import application
assert callable(application)

import importlib
importlib.import_module('django.core.management.commands.migrate')
importlib.import_module(
    'django.contrib.staticfiles.management.commands.collectstatic'
)

print('OK')
'''

    def test_django_boots_with_pymysql_only(self):
        import os
        import subprocess
        import sys

        project_dir = str(settings.BASE_DIR)
        script = self.BLOCK_AND_BOOT % project_dir

        result = subprocess.run(
            [sys.executable, '-c', script],
            capture_output=True,
            text=True,
            cwd=project_dir,
            timeout=180,
        )

        self.assertEqual(
            result.returncode,
            0,
            msg=f'stdout:\n{result.stdout}\nstderr:\n{result.stderr}',
        )
        self.assertIn('OK', result.stdout)


class GracefulDegradationTests(SimpleTestCase):
    """Optional subsystems must degrade instead of breaking the pipeline."""

    def test_visual_analyzer_returns_unavailable_without_playwright(self):
        import builtins

        from User.services.nikhil.visual_analyzer import VisualAnalyzer

        real_import = builtins.__import__

        def blocked_import(name, *args, **kwargs):
            if name.startswith('playwright'):
                raise ImportError('playwright is not installed')
            return real_import(name, *args, **kwargs)

        with mock.patch('builtins.__import__', side_effect=blocked_import):
            evidence = VisualAnalyzer.analyze_visual('http://example.com', scan_id=1)

        self.assertEqual(evidence['status'], 'UNAVAILABLE')
        self.assertIsNone(evidence['screenshot_reference'])
        self.assertIn('Playwright', evidence['error'])

    def test_visual_analyzer_keeps_safety_flags(self):
        from User.services.nikhil.visual_analyzer import VisualAnalyzer

        self.assertEqual(VisualAnalyzer.NAVIGATION_TIMEOUT_MS, 5000)
        self.assertEqual(VisualAnalyzer.TOTAL_TIMEOUT_MS, 10000)

    def test_mongodb_repository_degrades_without_uri(self):
        from User.services.nikhil.mongodb_repository import MongoDBRepository

        with _env_without('MONGODB_URI', 'MONGODB_DATABASE', 'MONGODB_COLLECTION'):
            repo = MongoDBRepository()

        self.assertFalse(repo.is_available())
        # Storing still returns a reference instead of raising.
        reference = repo.store_evidence({'scan_id': 999})
        self.assertEqual(reference, 'local-cache-scan-999')
        self.assertEqual(repo.get_evidence(999)['scan_id'], 999)

    def test_mongodb_defaults_match_expected_atlas_targets(self):
        from User.services.nikhil.mongodb_repository import MongoDBRepository

        with _env_without('MONGODB_URI', 'MONGODB_DATABASE', 'MONGODB_COLLECTION'):
            repo = MongoDBRepository()
        self.assertEqual(repo.db_name, 'nikhil_db')
        self.assertEqual(repo.collection_name, 'deep_analysis_cases')

    def test_webpage_analyzer_safety_limits_preserved(self):
        from User.services.nikhil.webpage_analyzer import WebpageAnalyzer

        self.assertEqual(WebpageAnalyzer.MAX_CONTENT_SIZE, 1024 * 1024)
        self.assertEqual(WebpageAnalyzer.MAX_REDIRECTS, 3)
        self.assertEqual(WebpageAnalyzer.TIMEOUT, (3.0, 5.0))

    def test_free_only_policy_defaults(self):
        from User.services.nikhil.ai_provider_base import is_free_only_mode
        from User.services.nikhil.free_only_guard import FreeOnlyGuard

        with _env_without('FREE_ONLY', 'ALLOW_PAID_PROVIDERS'):
            self.assertTrue(FreeOnlyGuard.is_free_only())
            self.assertFalse(FreeOnlyGuard.allow_paid_providers())
            self.assertTrue(is_free_only_mode())
            allowed, _ = FreeOnlyGuard.is_provider_allowed('threatfox')
            blocked, _ = FreeOnlyGuard.is_provider_allowed('virustotal')

        self.assertTrue(allowed)
        self.assertFalse(blocked)

    def test_ai_provider_attempt_limit(self):
        from User.services.nikhil.ai_provider_manager import AIProviderManager

        with mock.patch.dict(
            os.environ, {'AI_MAX_PROVIDER_ATTEMPTS': '2'}, clear=False
        ):
            self.assertEqual(AIProviderManager.MAX_PROVIDER_ATTEMPTS, 2)

    def test_openrouter_enforces_free_model_suffix(self):
        from User.services.nikhil.openrouter_provider import OpenRouterProvider

        with _env_without('OPENROUTER_MODEL'):
            provider = OpenRouterProvider()
        self.assertTrue(provider._validate_free_model())

        with mock.patch.dict(
            os.environ, {'OPENROUTER_MODEL': 'some/paid-model'}, clear=False
        ):
            self.assertFalse(OpenRouterProvider()._validate_free_model())


class UserDatabaseProvisioningTests(SimpleTestCase):
    """
    Tests for per-user database provisioning, recovery, idempotency, and concurrency:
    1. Fresh user DB provisioning.
    2. Existing fully migrated user DB.
    3. Existing DB + missing registry row.
    4. Partially migrated DB.
    5. Existing initial table + missing migration record.
    6. fake_initial recovery path.
    7. Later migrations still run.
    8. No duplicate registry rows.
    9. Repeated ensure_user_database() is idempotent.
    10. Health endpoint does not provision.
    11. Status endpoint does not provision.
    12. Dynamic DB retains Aiven SSL configuration.
    13. /predict GET succeeds after provisioning.
    14. Migration failure is still surfaced.
    """

    def setUp(self):
        super().setUp()
        self._initial_connections = set(connections.databases.keys())

    def tearDown(self):
        super().tearDown()
        for alias in list(connections.databases.keys()):
            if alias not in self._initial_connections:
                try:
                    connections[alias].close()
                except Exception:
                    pass
                del connections.databases[alias]

    @contextlib.contextmanager
    def _in_memory_user_db(self, alias='user_test_prov'):
        cfg = connections.databases['default'].copy()
        cfg['ENGINE'] = 'django.db.backends.sqlite3'
        cfg['NAME'] = ':memory:'
        cfg['OPTIONS'] = {}
        connections.databases[alias] = cfg
        saved_dbs = self.__class__.databases or frozenset()
        self.__class__.databases = frozenset(set(saved_dbs) | {alias})
        try:
            yield alias
        finally:
            self.__class__.databases = saved_dbs
            if alias in connections.databases:
                try:
                    connections[alias].close()
                except Exception:
                    pass
                del connections.databases[alias]

    def test_1_fresh_user_db_provisioning(self):
        """Case A: database does not exist -> create DB -> register connection -> migrate -> create registry row."""
        from User import db_manager
        from User.models import UserDatabaseRegistry

        user = mock.MagicMock(is_authenticated=True, id=42, username='fresh_user')

        mock_registry_mgr = mock.MagicMock()
        mock_registry_mgr.filter.return_value.first.return_value = None

        with mock.patch.object(UserDatabaseRegistry.objects, 'using', return_value=mock_registry_mgr), \
             mock.patch.object(db_manager, 'ensure_mysql_database_exists') as mock_ensure_db, \
             mock.patch.object(db_manager, 'reconcile_user_database_migrations') as mock_reconcile:
            alias = db_manager.ensure_user_database(user)

        self.assertEqual(alias, 'user_42')
        mock_ensure_db.assert_called_once_with('maliciousbot_user_000042')
        mock_reconcile.assert_called_once_with('user_42')
        mock_registry_mgr.update_or_create.assert_called_once_with(
            user_id=42,
            defaults={
                'username': 'fresh_user',
                'database_name': 'maliciousbot_user_000042',
                'status': 'active',
                'last_used_at': mock.ANY,
            }
        )

    def test_2_existing_fully_migrated_user_db(self):
        """Case B: database exists and registry exists -> register connection -> do NOT rerun provisioning -> update last_used_at."""
        from User import db_manager
        from User.models import UserDatabaseRegistry

        user = mock.MagicMock(is_authenticated=True, id=42, username='existing_user')
        existing_reg = mock.MagicMock(id=99, status='active')

        mock_registry_mgr = mock.MagicMock()
        mock_registry_mgr.filter.return_value.first.return_value = existing_reg

        with mock.patch.object(UserDatabaseRegistry.objects, 'using', return_value=mock_registry_mgr), \
             mock.patch.object(db_manager, 'ensure_mysql_database_exists') as mock_ensure_db, \
             mock.patch.object(db_manager, 'reconcile_user_database_migrations') as mock_reconcile:
            alias = db_manager.ensure_user_database(user)

        self.assertEqual(alias, 'user_42')
        mock_ensure_db.assert_not_called()
        mock_reconcile.assert_not_called()
        mock_registry_mgr.filter.return_value.update.assert_called_once()

    def test_3_existing_db_missing_registry_row(self):
        """Case C: database exists but registry row is missing -> inspect/reconcile -> complete migrations -> create registry row."""
        from User import db_manager
        from User.models import UserDatabaseRegistry

        user = mock.MagicMock(is_authenticated=True, id=42, username='reconcile_user')

        mock_registry_mgr = mock.MagicMock()
        mock_registry_mgr.filter.return_value.first.return_value = None

        with mock.patch.object(UserDatabaseRegistry.objects, 'using', return_value=mock_registry_mgr), \
             mock.patch.object(db_manager, 'ensure_mysql_database_exists') as mock_ensure_db, \
             mock.patch.object(db_manager, 'reconcile_user_database_migrations') as mock_reconcile:
            alias = db_manager.ensure_user_database(user)

        self.assertEqual(alias, 'user_42')
        mock_ensure_db.assert_called_once_with('maliciousbot_user_000042')
        mock_reconcile.assert_called_once_with('user_42')
        mock_registry_mgr.update_or_create.assert_called_once()

    def test_4_partially_migrated_db_recovery(self):
        """Case D: database exists and migration partially completed -> recover safely -> finish remaining migrations."""
        from django.core.management import call_command
        from django.db.migrations.recorder import MigrationRecorder
        from User.db_manager import reconcile_user_database_migrations

        with self._in_memory_user_db('test_partially_migrated') as alias:
            call_command('migrate', 'contenttypes', database=alias, verbosity=0)
            call_command('migrate', 'User', '0004', database=alias, verbosity=0)

            # Simulate interrupted 0004: remove from django_migrations so tables exist but record is missing
            conn = connections[alias]
            with conn.cursor() as cursor:
                cursor.execute(
                    "DELETE FROM django_migrations WHERE app=%s AND name=%s",
                    ['User', '0004_pari_schema']
                )

            recorder = MigrationRecorder(conn)
            self.assertNotIn(('User', '0004_pari_schema'), recorder.applied_migrations())

            # Reconcile: must succeed without crashing on table pari_domain already exists
            reconcile_user_database_migrations(alias)

            applied_names = [m[1] for m in recorder.applied_migrations() if m[0] == 'User']
            self.assertIn('0004_pari_schema', applied_names)
            self.assertIn('0011_scanfinaldecision_and_more', applied_names)

            # Ensure application tables exist
            with conn.cursor() as cursor:
                tables = set(conn.introspection.table_names(cursor))
            self.assertIn('pari_domain', tables)
            self.assertIn('pari_scan', tables)
            self.assertIn('pari_analyst_review', tables)
            self.assertIn('pari_final_decision', tables)

    def test_5_existing_initial_table_missing_migration_record(self):
        """Existing initial table with missing migration record triggers fake_initial."""
        from django.core.management import call_command
        from User.db_manager import reconcile_user_database_migrations

        with self._in_memory_user_db('test_initial_missing') as alias:
            call_command('migrate', 'contenttypes', database=alias, verbosity=0)
            call_command('migrate', 'User', '0004', database=alias, verbosity=0)

            conn = connections[alias]
            with conn.cursor() as cursor:
                cursor.execute(
                    "DELETE FROM django_migrations WHERE app=%s AND name=%s",
                    ['User', '0004_pari_schema']
                )

            with mock.patch('django.core.management.call_command', wraps=call_command) as mock_migrate:
                reconcile_user_database_migrations(alias)

            # Verify migrate was called with fake_initial=True
            called_fake_initial = any(
                kwargs.get('fake_initial') is True
                for _, _, kwargs in mock_migrate.mock_calls
                if kwargs.get('database') == alias
            )
            self.assertTrue(called_fake_initial)

    def test_6_fake_initial_recovery_path(self):
        """fake_initial=True is passed only when justified, not on completely empty DB."""
        from django.core.management import call_command
        from User.db_manager import reconcile_user_database_migrations

        with self._in_memory_user_db('test_empty_db') as alias:
            with mock.patch('django.core.management.call_command', wraps=call_command) as mock_migrate:
                reconcile_user_database_migrations(alias)

            called_fake_initial = any(
                kwargs.get('fake_initial') is True
                for _, _, kwargs in mock_migrate.mock_calls
                if kwargs.get('database') == alias
            )
            # Empty database has no initial tables, so fake_initial must be False
            self.assertFalse(called_fake_initial)

    def test_7_later_migrations_still_run(self):
        """Later migrations (0005 to 0011) run genuinely after initial tables are reconciled."""
        from django.core.management import call_command
        from django.db.migrations.recorder import MigrationRecorder
        from User.db_manager import reconcile_user_database_migrations

        with self._in_memory_user_db('test_later_migrations') as alias:
            call_command('migrate', 'contenttypes', database=alias, verbosity=0)
            call_command('migrate', 'User', '0004', database=alias, verbosity=0)

            conn = connections[alias]
            with conn.cursor() as cursor:
                cursor.execute(
                    "DELETE FROM django_migrations WHERE app=%s AND name=%s",
                    ['User', '0004_pari_schema']
                )

            reconcile_user_database_migrations(alias)

            recorder = MigrationRecorder(conn)
            applied = [m[1] for m in recorder.applied_migrations() if m[0] == 'User']
            for expected in ('0005_analystreview_and_more', '0007_pari_scan_features',
                             '0008_phase3_separate_initial_fallback', '0011_scanfinaldecision_and_more'):
                self.assertIn(expected, applied)

    def test_8_no_duplicate_registry_rows(self):
        """Registry consistency ensures update_or_create prevents duplicate rows."""
        from User import db_manager
        from User.models import UserDatabaseRegistry

        user = mock.MagicMock(is_authenticated=True, id=77, username='no_dup_user')

        mock_registry_mgr = mock.MagicMock()
        mock_registry_mgr.filter.return_value.first.return_value = None

        with mock.patch.object(UserDatabaseRegistry.objects, 'using', return_value=mock_registry_mgr), \
             mock.patch.object(db_manager, 'ensure_mysql_database_exists'), \
             mock.patch.object(db_manager, 'reconcile_user_database_migrations'):
            db_manager.ensure_user_database(user)

        self.assertEqual(mock_registry_mgr.update_or_create.call_count, 1)
        self.assertEqual(mock_registry_mgr.create.call_count, 0)

    def test_9_repeated_ensure_user_database_is_idempotent(self):
        """Repeated ensure_user_database calls return same alias and do not re-provision."""
        from User import db_manager
        from User.models import UserDatabaseRegistry

        user = mock.MagicMock(is_authenticated=True, id=88, username='idempotent_user')

        mock_registry_mgr = mock.MagicMock()
        created_entry = []

        def fake_first():
            return created_entry[0] if created_entry else None

        mock_registry_mgr.filter.return_value.first.side_effect = fake_first

        def fake_update_or_create(**kwargs):
            entry = mock.MagicMock(id=88, status='active')
            created_entry.append(entry)
            return entry, True

        mock_registry_mgr.update_or_create.side_effect = fake_update_or_create

        with mock.patch.object(UserDatabaseRegistry.objects, 'using', return_value=mock_registry_mgr), \
             mock.patch.object(db_manager, 'ensure_mysql_database_exists') as mock_ensure, \
             mock.patch.object(db_manager, 'reconcile_user_database_migrations') as mock_reconcile:
            alias1 = db_manager.ensure_user_database(user)
            alias2 = db_manager.ensure_user_database(user)

        self.assertEqual(alias1, 'user_88')
        self.assertEqual(alias2, 'user_88')
        # DB provisioning and migration should only run once
        self.assertEqual(mock_ensure.call_count, 1)
        self.assertEqual(mock_reconcile.call_count, 1)

    def test_10_health_endpoint_does_not_provision(self):
        """Health endpoint skips user database provisioning."""
        with mock.patch('User.middleware.ensure_user_database') as mock_ensure, \
             stubbed_connection_cursor():
            response = self.client.get('/health')
        self.assertEqual(response.status_code, 200)
        mock_ensure.assert_not_called()

    def test_11_status_endpoint_does_not_provision(self):
        """Status endpoint skips user database provisioning."""
        with mock.patch('User.middleware.ensure_user_database') as mock_ensure, \
             stubbed_connection_cursor():
            response = self.client.get('/status')
        self.assertEqual(response.status_code, 200)
        mock_ensure.assert_not_called()

    def test_12_dynamic_db_retains_aiven_ssl_configuration(self):
        """Dynamic user database inherits identical host, port, credentials, and SSL."""
        from User.db_manager import get_mysql_db_config

        default = settings.DATABASES['default']
        cfg = get_mysql_db_config('maliciousbot_user_000001')

        self.assertEqual(cfg['NAME'], 'maliciousbot_user_000001')
        self.assertEqual(cfg['CONN_MAX_AGE'], 0)
        self.assertEqual(cfg['OPTIONS']['charset'], 'utf8mb4')
        self.assertEqual(cfg['OPTIONS']['init_command'], "SET sql_mode='STRICT_TRANS_TABLES'")
        self.assertEqual(
            default['OPTIONS'].get('ssl') is not None,
            cfg['OPTIONS'].get('ssl') is not None
        )

    def test_13_predict_get_succeeds_after_provisioning(self):
        """GET /predict succeeds after provisioning without training ML models."""
        from django.test import RequestFactory
        from django.contrib.sessions.middleware import SessionMiddleware
        from django.contrib.messages.middleware import MessageMiddleware
        from User import views
        from User.middleware import UserDatabaseMiddleware

        factory = RequestFactory()
        request = factory.get('/predict')
        request.user = mock.MagicMock(is_authenticated=True, id=5, username='predict_user')
        SessionMiddleware(lambda r: None).process_request(request)
        MessageMiddleware(lambda r: None).process_request(request)

        with mock.patch('User.middleware.ensure_user_database', return_value='user_5') as mock_ensure, \
             mock.patch.object(views, 'train_model') as mock_train:
            middleware = UserDatabaseMiddleware(lambda req: views.predict(req))
            response = middleware(request)

        self.assertEqual(response.status_code, 200)
        mock_ensure.assert_called_once_with(request.user)
        mock_train.assert_not_called()

    def test_14_migration_failure_is_still_surfaced(self):
        """Migration errors are logged and re-raised, not silently swallowed."""
        from django.db.utils import OperationalError
        from User import db_manager
        from User.models import UserDatabaseRegistry

        user = mock.MagicMock(is_authenticated=True, id=99, username='failing_user')

        mock_registry_mgr = mock.MagicMock()
        mock_registry_mgr.filter.return_value.first.return_value = None

        with self._in_memory_user_db('user_99') as alias, \
             mock.patch.object(UserDatabaseRegistry.objects, 'using', return_value=mock_registry_mgr), \
             mock.patch.object(db_manager, 'ensure_mysql_database_exists'), \
             mock.patch('django.core.management.call_command', side_effect=OperationalError('Simulated SQL error')):
            with self.assertRaises(OperationalError):
                db_manager.ensure_user_database(user)
