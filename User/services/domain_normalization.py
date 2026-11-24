"""
Centralized URL / hostname / registered-domain normalization.

Single source of truth for how MaliciousBot stores and correlates domains:

* ``pari_domain.domain_name`` stores the **registered domain** (public-suffix
  aware), e.g. ``www.google.co.in`` -> ``google.co.in``.
* ``pari_domain.tld`` stores the **public suffix**, e.g. ``co.in``.
* IP-literal URLs are stored under the canonical IP string (no suffix).
* Hostnames without a public suffix (``localhost``, intranet names) are stored
  under the normalized hostname itself.

The PARI Random Forest features are intentionally NOT changed by this module:
``views.extract_root_domain`` (the label used for the ``root_domain`` /
``url_region`` features) keeps its original behaviour so the trained model and
feature semantics remain identical.

A bundled public-suffix snapshot is used (no network fetch), which makes the
result deterministic across workers and test runs.
"""

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlsplit

import tldextract

# Offline extractor: uses the public-suffix snapshot bundled with tldextract.
_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

_LABEL_RE = re.compile(r'^(?!-)[a-z0-9-]{1,63}(?<!-)$')
_SCHEME_RE = re.compile(r'^[a-zA-Z][a-zA-Z0-9+.-]*://')


@dataclass(frozen=True)
class NormalizedURL:
    original: str
    url: str                       # URL with an explicit scheme
    scheme: str
    hostname: str                  # lowercase, IDNA (punycode), no trailing dot
    port: Optional[int]
    is_ip: bool
    ip: Optional[str]              # canonical IP string when is_ip
    registered_domain: str         # storage key for pari_domain.domain_name
    domain_label: str              # e.g. "google"
    suffix: str                    # e.g. "co.in" ('' for IPs / suffix-less hosts)
    subdomain: str                 # e.g. "www"
    valid: bool = True
    errors: tuple = field(default_factory=tuple)


def normalize_hostname(host: str) -> str:
    """Lowercase, strip brackets / trailing dots and IDNA-encode a hostname."""
    if host is None:
        return ''
    host = str(host).strip().strip('[]').rstrip('.').lower()
    if not host:
        return ''
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    try:
        return host.encode('idna').decode('ascii')
    except (UnicodeError, ValueError):
        return host


def parse_ip(host: str):
    """Return an ipaddress object for a strict IP literal, else None."""
    if not host:
        return None
    candidate = host.strip('[]')
    if '%' in candidate:  # IPv6 zone identifiers are never accepted
        return None
    try:
        return ipaddress.ip_address(candidate)
    except ValueError:
        return None


def ensure_scheme(url: str) -> str:
    url = (url or '').strip()
    if not _SCHEME_RE.match(url):
        url = 'http://' + url
    return url


def normalize_url(url: str) -> NormalizedURL:
    """Parse and normalize a URL (never raises)."""
    original = url if url is not None else ''
    errors = []
    full = ensure_scheme(original)
    try:
        parts = urlsplit(full)
        scheme = (parts.scheme or 'http').lower()
        raw_host = parts.hostname or ''
        try:
            port = parts.port
        except ValueError:
            port = None
            errors.append('invalid_port')
    except ValueError:
        return NormalizedURL(original, full, 'http', '', None, False, None, '', '', '', '',
                             valid=False, errors=('unparseable_url',))

    hostname = normalize_hostname(raw_host)
    if not hostname:
        errors.append('missing_hostname')

    ip_obj = parse_ip(hostname)
    if ip_obj is not None:
        canonical = str(ip_obj)
        return NormalizedURL(original, full, scheme, canonical, port, True, canonical,
                             canonical, canonical, '', '', valid=not errors, errors=tuple(errors))

    ext = _EXTRACTOR(hostname) if hostname else None
    if ext is not None and ext.suffix and ext.domain:
        registered = f"{ext.domain}.{ext.suffix}"
        label, suffix, sub = ext.domain, ext.suffix, ext.subdomain
    else:
        registered = hostname
        label, suffix, sub = (hostname.split('.')[0] if hostname else ''), '', ''
        if hostname:
            errors.append('no_public_suffix')

    for lbl in hostname.split('.') if hostname else []:
        if not _LABEL_RE.match(lbl):
            errors.append('invalid_hostname_label')
            break

    return NormalizedURL(
        original, full, scheme, hostname, port, False, None,
        registered, label, suffix, sub,
        valid=not [e for e in errors if e != 'no_public_suffix'],
        errors=tuple(errors),
    )


def registered_domain_for(url_or_host: str) -> str:
    """Registered domain for a URL or bare hostname ('' if none)."""
    return normalize_url(url_or_host).registered_domain


def suffix_for(url_or_host: str) -> Optional[str]:
    s = normalize_url(url_or_host).suffix
    return s or None
