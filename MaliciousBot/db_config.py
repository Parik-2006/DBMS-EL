"""
Aiven MySQL SSL/TLS configuration helper.

Single source of truth for MySQL TLS options. Imported by both
``MaliciousBot.settings`` (for the ``default`` / ``guest_db`` connections) and
``User.db_manager`` (for the raw admin provisioning connection), so every MySQL
connection in the project receives identical SSL configuration.

Environment variables
---------------------
MYSQL_SSL_MODE
    One of ``DISABLED``, ``REQUIRED``, ``VERIFY_CA``, ``VERIFY_IDENTITY``.
    When unset the mode is derived automatically (see ``resolve_mysql_ssl_mode``).

MYSQL_SSL_CA
    The Aiven project CA certificate. Accepts either:
      * a filesystem path to a PEM file (e.g. a Render secret file mount), or
      * the inline PEM text itself (``-----BEGIN CERTIFICATE-----`` ...).

The certificate is never committed to source control: it is supplied purely
through the environment.
"""

import os
import ssl

# Modes that require a server certificate to be verified against a CA.
VERIFYING_MODES = frozenset({'VERIFY_CA', 'VERIFY_IDENTITY'})

# Modes that turn TLS on without verifying the server certificate.
ENCRYPT_ONLY_MODES = frozenset({'REQUIRED'})

VALID_MODES = frozenset({'DISABLED', 'REQUIRED', 'VERIFY_CA', 'VERIFY_IDENTITY'})

LOCAL_HOSTS = frozenset({'localhost', '127.0.0.1', '::1', ''})

_PEM_MARKER = 'BEGIN CERTIFICATE'


class MySQLSSLConfigurationError(RuntimeError):
    """Raised when MySQL SSL configuration is required but invalid or missing."""


def _is_local_host(host):
    return str(host or '').strip().lower() in LOCAL_HOSTS


def resolve_mysql_ssl_mode(mysql_host=None):
    """
    Determine the effective SSL mode.

    Explicit ``MYSQL_SSL_MODE`` always wins and is validated.

    Otherwise the mode is derived so that ordinary local development keeps
    working while any remote deployment gets TLS:

        * local host            -> DISABLED (unchanged local behaviour)
        * remote host + CA set  -> VERIFY_CA   (encrypted *and* authenticated)
        * remote host, no CA    -> REQUIRED    (encrypted, not authenticated)
    """
    raw_mode = str(os.environ.get('MYSQL_SSL_MODE', '') or '').strip().upper()

    if raw_mode:
        if raw_mode not in VALID_MODES:
            raise MySQLSSLConfigurationError(
                f"MYSQL_SSL_MODE={raw_mode!r} is not supported. "
                f"Choose one of: {', '.join(sorted(VALID_MODES))}."
            )
        return raw_mode

    if mysql_host is None:
        mysql_host = os.environ.get('MYSQL_HOST', '')

    if _is_local_host(mysql_host):
        return 'DISABLED'

    if str(os.environ.get('MYSQL_SSL_CA', '') or '').strip():
        return 'VERIFY_CA'

    return 'REQUIRED'


def _build_ssl_context(mode, ca_setting):
    """Build an :class:`ssl.SSLContext` for the requested verification mode."""
    ca_setting = str(ca_setting or '').strip()

    if mode in VERIFYING_MODES and not ca_setting:
        raise MySQLSSLConfigurationError(
            f"MYSQL_SSL_MODE={mode} requires MYSQL_SSL_CA to be set so the Aiven "
            "server certificate can be verified. Refusing to start without it."
        )

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2

    if mode in ENCRYPT_ONLY_MODES and not ca_setting:
        # REQUIRED without a CA: still negotiate TLS, but do not authenticate the
        # server. Nothing is verified, so no trust store is loaded.
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context

    if _PEM_MARKER in ca_setting:
        context.load_verify_locations(cadata=ca_setting)
    else:
        # Treat as a filesystem path (Render secret file mount, etc.).
        if not os.path.isfile(ca_setting):
            raise MySQLSSLConfigurationError(
                "MYSQL_SSL_CA does not point to a readable PEM file and does not "
                "contain inline certificate data."
            )
        context.load_verify_locations(cafile=ca_setting)

    # Both verifying modes require a valid chain. Only VERIFY_IDENTITY also
    # checks that the certificate matches the server hostname.
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = mode == 'VERIFY_IDENTITY'

    return context


def get_mysql_ssl_options(mysql_host=None):
    """
    Return the ``ssl`` keyword arguments for a PyMySQL/MySQLdb connection.

    Returns an empty dict when TLS is not in use, so callers can merge the
    result unconditionally.
    """
    mode = resolve_mysql_ssl_mode(mysql_host)

    if mode == 'DISABLED':
        return {}

    ca_setting = os.environ.get('MYSQL_SSL_CA', '')

    return {'ssl': _build_ssl_context(mode, ca_setting)}


def get_mysql_ssl_ca(mysql_host=None):
    """Return the raw ``MYSQL_SSL_CA`` value, or ``''`` when unset."""
    if resolve_mysql_ssl_mode(mysql_host) == 'DISABLED':
        return ''
    return str(os.environ.get('MYSQL_SSL_CA', '') or '').strip()
