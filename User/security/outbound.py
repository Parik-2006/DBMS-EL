"""
Outbound URL security policy (SSRF protection).

Every collector that contacts a user-supplied destination (webpage fetch, HEAD
metadata, TLS inspection, browser screenshot sub-requests) MUST go through this
module. Design:

1. ``validate_url`` parses the URL strictly, enforces scheme / port / host rules,
   rejects credentials, ambiguous or non-canonical IP representations and
   internal hostnames, resolves DNS and requires *every* resolved address to be
   a public, globally routable IP. It fails closed.
2. ``safe_request`` connects to the **already validated IP** (DNS pinning), so a
   second DNS answer (DNS rebinding) can never redirect the connection. TLS is
   still verified against the original hostname (SNI + hostname check).
3. Redirects are never followed automatically; each ``Location`` is validated as
   a brand-new destination, up to an explicit redirect limit.
4. Connect / read / overall timeouts and a response-size cap are enforced.
"""

import ipaddress
import logging
import os
import re
import socket
import ssl
import time
import concurrent.futures
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlsplit, urlunsplit

logger = logging.getLogger(__name__)

ALLOWED_SCHEMES = ('http', 'https')
DEFAULT_PORTS = {'http': 80, 'https': 443}
DEFAULT_ALLOWED_PORTS = frozenset({80, 443, 8080, 8443})
MAX_URL_LENGTH = 2048
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})

# Hostnames / suffixes that must never be contacted regardless of DNS answers.
BLOCKED_HOSTNAMES = frozenset({
    'localhost', 'localhost.localdomain', 'ip6-localhost', 'ip6-loopback',
    'metadata', 'metadata.google.internal', 'metadata.goog', 'instance-data',
    'instance-data.ec2.internal', 'kubernetes.default', 'kubernetes.default.svc',
})
BLOCKED_HOST_SUFFIXES = (
    '.localhost', '.local', '.localdomain', '.internal', '.intranet', '.lan',
    '.home.arpa', '.corp', '.svc', '.cluster.local',
)
# Explicit cloud metadata endpoints (also covered by the generic range checks).
METADATA_IPS = frozenset({
    ipaddress.ip_address('169.254.169.254'),
    ipaddress.ip_address('169.254.170.2'),
    ipaddress.ip_address('100.100.100.200'),
    ipaddress.ip_address('fd00:ec2::254'),
})

_NUMERIC_LABEL = re.compile(r'^(0x[0-9a-f]*|[0-9]+)$')
_HOST_LABEL = re.compile(r'^(?!-)[a-z0-9_-]{1,63}(?<!-)$')
_CONTROL_CHARS = re.compile(r'[\x00-\x20\x7f\\]')


class OutboundBlocked(Exception):
    """Destination rejected by policy (security block). Never means 'benign'."""

    def __init__(self, reason: str, detail: str = ''):
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else reason)


class OutboundError(Exception):
    """Destination could not be reached / validated reliably (unavailable)."""

    def __init__(self, reason: str, detail: str = ''):
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else reason)


@dataclass
class ValidatedTarget:
    url: str
    scheme: str
    host: str            # ASCII (IDNA) hostname or canonical IP
    port: int
    addresses: List[str]
    is_ip_literal: bool
    path_and_query: str

    @property
    def host_header(self) -> str:
        host = f"[{self.host}]" if ':' in self.host else self.host
        if self.port != DEFAULT_PORTS[self.scheme]:
            return f"{host}:{self.port}"
        return host


@dataclass
class SafeResponse:
    url: str
    status: int
    headers: Dict[str, str]
    body: bytes
    history: List[str] = field(default_factory=list)
    truncated: bool = False
    peer_ip: Optional[str] = None
    elapsed: float = 0.0


def allowed_ports() -> frozenset:
    raw = os.environ.get('OUTBOUND_ALLOWED_PORTS', '').strip()
    if not raw:
        return DEFAULT_ALLOWED_PORTS
    ports = set()
    for item in raw.split(','):
        item = item.strip()
        if item.isdigit() and 0 < int(item) < 65536:
            ports.add(int(item))
    return frozenset(ports) or DEFAULT_ALLOWED_PORTS


# ---------------------------------------------------------------------------
# IP classification
# ---------------------------------------------------------------------------
def ip_block_reason(ip) -> Optional[str]:
    """Return a reason string if the IP is not a public destination, else None."""
    if isinstance(ip, str):
        ip = ipaddress.ip_address(ip)
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            inner = ip_block_reason(ip.ipv4_mapped)
            return f"ipv4_mapped_{inner}" if inner else None
        if ip.sixtofour is not None:
            inner = ip_block_reason(ip.sixtofour)
            if inner:
                return f"6to4_{inner}"
        if ip.teredo is not None:
            for embedded in ip.teredo:
                inner = ip_block_reason(embedded)
                if inner:
                    return f"teredo_{inner}"
        if ip.is_site_local:
            return 'site_local'
    if ip in METADATA_IPS:
        return 'cloud_metadata'
    checks = (
        ('unspecified', ip.is_unspecified),
        ('loopback', ip.is_loopback),
        ('link_local', ip.is_link_local),
        ('multicast', ip.is_multicast),
        ('private', ip.is_private),
        ('reserved', ip.is_reserved),
    )
    for name, flag in checks:
        if flag:
            return name
    if not ip.is_global:
        return 'non_global'
    return None


def is_public_ip(ip) -> bool:
    try:
        return ip_block_reason(ip) is None
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# DNS resolution (injectable for tests)
# ---------------------------------------------------------------------------
def _system_resolve(host: str, port: int) -> List[str]:
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    seen = []
    for info in infos:
        addr = info[4][0]
        if addr not in seen:
            seen.append(addr)
    return seen


_resolver: Callable[[str, int], List[str]] = _system_resolve
_dns_pool = concurrent.futures.ThreadPoolExecutor(max_workers=4, thread_name_prefix='outbound-dns')


def set_resolver(func: Optional[Callable[[str, int], List[str]]]):
    """Install a custom resolver (tests). ``None`` restores the system resolver."""
    global _resolver
    _resolver = func or _system_resolve


def resolve_host(host: str, port: int, timeout: float = 3.0) -> List[str]:
    future = _dns_pool.submit(_resolver, host, port)
    try:
        return list(future.result(timeout=timeout))
    except concurrent.futures.TimeoutError:
        raise OutboundError('dns_timeout', host)
    except (socket.gaierror, OSError, UnicodeError) as exc:
        raise OutboundError('dns_resolution_failed', f"{host}: {type(exc).__name__}")


# ---------------------------------------------------------------------------
# URL validation
# ---------------------------------------------------------------------------
def _normalize_host(raw_host: str) -> Tuple[str, bool]:
    """Return (ascii_host, is_ip_literal) or raise OutboundBlocked."""
    host = raw_host.strip()
    if not host:
        raise OutboundBlocked('malformed_url', 'missing host')
    if '%' in host:
        raise OutboundBlocked('ambiguous_host', 'IPv6 zone identifiers are not allowed')
    bracketed = host.startswith('[') and host.endswith(']')
    candidate = host[1:-1] if bracketed else host
    if candidate.endswith('.'):
        candidate = candidate[:-1]
    if not candidate or candidate.endswith('.'):
        raise OutboundBlocked('malformed_url', 'invalid trailing dots')
    candidate = candidate.lower()

    try:
        ip = ipaddress.ip_address(candidate)
        if isinstance(ip, ipaddress.IPv6Address) and not bracketed:
            raise OutboundBlocked('ambiguous_host', 'IPv6 literal must be bracketed')
        return str(ip), True
    except ValueError:
        if bracketed:
            raise OutboundBlocked('ambiguous_host', 'invalid bracketed IP literal')

    labels = candidate.split('.')
    if all(_NUMERIC_LABEL.match(lbl) for lbl in labels) or _NUMERIC_LABEL.match(labels[-1] or 'x'):
        # Decimal/octal/hex/short forms such as 2130706433, 0x7f.1, 127.1, 0177.0.0.1
        raise OutboundBlocked('noncanonical_ip', 'alternate IP representations are not allowed')

    try:
        ascii_host = candidate.encode('idna').decode('ascii')
    except (UnicodeError, ValueError):
        raise OutboundBlocked('malformed_url', 'invalid internationalized hostname')
    if len(ascii_host) > 253:
        raise OutboundBlocked('malformed_url', 'hostname too long')
    for lbl in ascii_host.split('.'):
        if not _HOST_LABEL.match(lbl):
            raise OutboundBlocked('malformed_url', 'invalid hostname label')
    if ascii_host in BLOCKED_HOSTNAMES or ascii_host.endswith(BLOCKED_HOST_SUFFIXES):
        raise OutboundBlocked('internal_hostname', ascii_host)
    if '.' not in ascii_host:
        raise OutboundBlocked('internal_hostname', 'single-label hostnames are not allowed')
    return ascii_host, False


def validate_url(url: str, *, resolve: bool = True, dns_timeout: float = 3.0) -> ValidatedTarget:
    """Validate a destination URL against the outbound policy (fail closed)."""
    if not isinstance(url, str) or not url.strip():
        raise OutboundBlocked('malformed_url', 'empty url')
    url = url.strip()
    if len(url) > MAX_URL_LENGTH:
        raise OutboundBlocked('malformed_url', 'url too long')
    if _CONTROL_CHARS.search(url):
        raise OutboundBlocked('malformed_url', 'control characters, whitespace or backslashes')
    try:
        parts = urlsplit(url)
    except ValueError:
        raise OutboundBlocked('malformed_url', 'unparseable')
    scheme = (parts.scheme or '').lower()
    if scheme not in ALLOWED_SCHEMES:
        raise OutboundBlocked('unsupported_scheme', scheme or 'none')
    netloc = parts.netloc
    if not netloc:
        raise OutboundBlocked('malformed_url', 'missing authority')
    if '@' in netloc:
        raise OutboundBlocked('credentials_in_url', 'embedded user information is not allowed')

    host_part = netloc
    port = None
    if host_part.startswith('['):
        end = host_part.find(']')
        if end == -1:
            raise OutboundBlocked('malformed_url', 'unterminated IPv6 literal')
        rest = host_part[end + 1:]
        host_raw = host_part[:end + 1]
        if rest:
            if not rest.startswith(':'):
                raise OutboundBlocked('malformed_url', 'invalid authority')
            port = rest[1:]
    else:
        if host_part.count(':') > 1:
            raise OutboundBlocked('ambiguous_host', 'unbracketed IPv6 or multiple ports')
        host_raw, _, port = host_part.partition(':')
        if not _:
            port = None
    if port is not None:
        if not port.isdigit() or not (0 < int(port) < 65536):
            raise OutboundBlocked('invalid_port', str(port)[:10])
        port = int(port)
    else:
        port = DEFAULT_PORTS[scheme]
    if port not in allowed_ports():
        raise OutboundBlocked('port_not_allowed', str(port))

    host, is_ip = _normalize_host(host_raw)

    if is_ip:
        reason = ip_block_reason(host)
        if reason:
            raise OutboundBlocked('non_public_destination', f"{host} ({reason})")
        addresses = [host]
    elif resolve:
        addresses = resolve_host(host, port, timeout=dns_timeout)
        if not addresses:
            raise OutboundError('dns_resolution_failed', host)
        for addr in addresses:
            try:
                reason = ip_block_reason(addr)
            except ValueError:
                raise OutboundBlocked('non_public_destination', f"unparseable address for {host}")
            if reason:
                # Mixed public/private answers are rejected entirely (fail closed).
                raise OutboundBlocked('non_public_destination', f"{host} -> {addr} ({reason})")
    else:
        addresses = []

    path = parts.path or '/'
    path_and_query = urlunsplit(('', '', path, parts.query, ''))
    canonical = urlunsplit((scheme, netloc.lower() if not is_ip else netloc, path, parts.query, ''))
    return ValidatedTarget(canonical, scheme, host, port, addresses, is_ip, path_and_query)


def check_url(url: str, resolve: bool = True) -> Tuple[bool, str]:
    """Non-raising helper: (allowed, reason)."""
    try:
        validate_url(url, resolve=resolve)
        return True, 'allowed'
    except (OutboundBlocked, OutboundError) as exc:
        return False, exc.reason


# ---------------------------------------------------------------------------
# Pinned transport
# ---------------------------------------------------------------------------
def _ca_bundle():
    try:
        import certifi
        return certifi.where()
    except ImportError:  # pragma: no cover
        return None


def _make_pool(target: ValidatedTarget, ip: str, connect_timeout: float, read_timeout: float):
    import urllib3
    timeout = urllib3.Timeout(connect=connect_timeout, read=read_timeout)
    if target.scheme == 'https':
        return urllib3.HTTPSConnectionPool(
            host=ip, port=target.port, timeout=timeout, retries=False, maxsize=1,
            cert_reqs='CERT_REQUIRED', ca_certs=_ca_bundle(),
            server_hostname=None if target.is_ip_literal else target.host,
            assert_hostname=target.host,
        )
    return urllib3.HTTPConnectionPool(host=ip, port=target.port, timeout=timeout,
                                      retries=False, maxsize=1)


def safe_request(url: str, method: str = 'GET', *, headers: Optional[Dict[str, str]] = None,
                 max_bytes: int = 1024 * 1024, max_redirects: int = 3,
                 connect_timeout: float = 3.0, read_timeout: float = 5.0,
                 total_timeout: float = 15.0, read_body: bool = True,
                 pool_factory=None) -> SafeResponse:
    """
    Perform an HTTP(S) request to a policy-validated, DNS-pinned destination.

    Raises OutboundBlocked (policy) or OutboundError (network/TLS/timeout).
    """
    import urllib3

    method = method.upper()
    if method not in ('GET', 'HEAD'):
        raise OutboundBlocked('method_not_allowed', method)
    pool_factory = pool_factory or _make_pool
    start = time.monotonic()
    history: List[str] = []
    current = url
    base_headers = {k: v for k, v in (headers or {}).items() if k.lower() not in ('host', 'cookie', 'authorization')}

    while True:
        remaining = total_timeout - (time.monotonic() - start)
        if remaining <= 0:
            raise OutboundError('timeout', 'overall request deadline exceeded')
        target = validate_url(current, dns_timeout=min(3.0, remaining))
        ip = target.addresses[0]
        pool = pool_factory(target, ip, min(connect_timeout, remaining), min(read_timeout, remaining))
        req_headers = dict(base_headers)
        req_headers['Host'] = target.host_header
        try:
            resp = pool.urlopen(method, target.path_and_query, headers=req_headers, redirect=False,
                                retries=False, preload_content=False, assert_same_host=False)
        except urllib3.exceptions.SSLError as exc:
            raise OutboundError('tls_error', type(exc).__name__)
        except (urllib3.exceptions.ConnectTimeoutError, urllib3.exceptions.ReadTimeoutError,
                socket.timeout) as exc:
            raise OutboundError('timeout', type(exc).__name__)
        except urllib3.exceptions.HTTPError as exc:
            raise OutboundError('connection_failed', type(exc).__name__)
        except OSError as exc:
            raise OutboundError('connection_failed', type(exc).__name__)

        status = resp.status
        resp_headers = {k: v for k, v in resp.headers.items()}
        location = resp.headers.get('Location')
        if status in REDIRECT_STATUSES and location:
            try:
                resp.release_conn()
            except Exception:
                pass
            history.append(target.url)
            if len(history) > max_redirects:
                raise OutboundBlocked('too_many_redirects', f"limit {max_redirects}")
            current = urljoin(target.url, location)
            if status == 303:
                method = 'GET' if method != 'HEAD' else 'HEAD'
            continue

        body = bytearray()
        truncated = False
        if read_body and method != 'HEAD':
            try:
                for chunk in resp.stream(8192):
                    body.extend(chunk)
                    if len(body) > max_bytes:
                        body = body[:max_bytes]
                        truncated = True
                        break
                    if time.monotonic() - start > total_timeout:
                        truncated = True
                        break
            except (urllib3.exceptions.ReadTimeoutError, socket.timeout) as exc:
                raise OutboundError('timeout', type(exc).__name__)
            except urllib3.exceptions.HTTPError as exc:
                raise OutboundError('connection_failed', type(exc).__name__)
        try:
            resp.release_conn()
        except Exception:
            pass
        return SafeResponse(url=target.url, status=status, headers=resp_headers, body=bytes(body),
                            history=history + [target.url] if history else [], truncated=truncated,
                            peer_ip=ip, elapsed=time.monotonic() - start)


def inspect_tls(url: str, timeout: float = 3.0, port: int = 443) -> dict:
    """
    Fetch the TLS certificate of a validated destination, connecting to the
    pinned IP while verifying the certificate against the hostname.

    Returns {"verified": bool|None, "cert": dict|None, "error": str|None}.
    ``verified`` is None when no TLS handshake could be completed (e.g. port
    closed) -- this must not be interpreted as an invalid certificate.
    """
    parts = urlsplit(url)
    if '@' in (parts.netloc or ''):
        raise OutboundBlocked('credentials_in_url', 'embedded user information is not allowed')
    host = parts.hostname or ''
    netloc = f"[{host}]:{port}" if ':' in host else f"{host}:{port}"
    target = validate_url(urlunsplit(('https', netloc, '/', '', '')))
    ip = target.addresses[0]
    context = ssl.create_default_context(cafile=_ca_bundle())
    try:
        with socket.create_connection((ip, target.port), timeout=timeout) as sock:
            server_name = None if target.is_ip_literal else target.host
            with context.wrap_socket(sock, server_hostname=server_name) as ssock:
                return {"verified": True, "cert": ssock.getpeercert(), "error": None, "peer_ip": ip}
    except ssl.SSLCertVerificationError as exc:
        return {"verified": False, "cert": None, "error": f"certificate verification failed: {exc.verify_message}",
                "peer_ip": ip}
    except (socket.timeout, TimeoutError):
        return {"verified": None, "cert": None, "error": "TLS connection timed out", "peer_ip": ip}
    except ConnectionRefusedError:
        return {"verified": None, "cert": None, "error": f"port {target.port} connection refused", "peer_ip": ip}
    except (ssl.SSLError, OSError) as exc:
        return {"verified": None, "cert": None, "error": f"TLS handshake failed: {type(exc).__name__}",
                "peer_ip": ip}
