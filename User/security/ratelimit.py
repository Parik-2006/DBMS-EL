"""
Cache-backed fixed-window rate limiting (no paid infrastructure).

Backend: the Django cache alias ``RATELIMIT_CACHE_ALIAS`` (default 'default').
* Local / single-worker: LocMemCache (per process; documented limitation).
* Multi-worker / multi-instance: set ``CACHE_BACKEND=database`` to use Django's
  DatabaseCache in the core MySQL database (shared, free). Requires
  ``python manage.py createcachetable`` (run by build.sh).

Limits are configured with env vars ``RATE_LIMIT_<SCOPE>='<count>/<seconds>'``.
Client IPs come from REMOTE_ADDR unless ``TRUSTED_PROXY_COUNT`` > 0, in which
case the N-th address from the right of X-Forwarded-For is used (Render sets
X-Forwarded-For; untrusted client-supplied entries to the left are ignored).
"""

import hashlib
import logging
import os
import time
from typing import Optional, Tuple

from django.conf import settings
from django.core.cache import caches

logger = logging.getLogger(__name__)

DEFAULT_RATES = {
    'login_ip': '20/300',
    'login_user': '5/300',
    'register': '10/3600',
    'scan': '20/600',
    'api': '120/60',
    'review': '60/600',
}


def rate_limiting_enabled() -> bool:
    return str(os.environ.get('RATE_LIMIT_ENABLED', getattr(settings, 'RATE_LIMIT_ENABLED', True))).lower() \
        in ('true', '1', 'yes', 'on')


def parse_rate(value: str) -> Tuple[int, int]:
    try:
        count, window = str(value).split('/', 1)
        count, window = int(count), int(window)
        if count <= 0 or window <= 0:
            raise ValueError
        return count, window
    except (ValueError, TypeError):
        raise ValueError(f"Invalid rate {value!r}; expected '<count>/<seconds>'")


def get_rate(scope: str) -> Tuple[int, int]:
    env = os.environ.get(f"RATE_LIMIT_{scope.upper()}")
    configured = getattr(settings, 'RATE_LIMITS', {}) or {}
    return parse_rate(env or configured.get(scope) or DEFAULT_RATES[scope])


def client_ip(request) -> str:
    remote = request.META.get('REMOTE_ADDR', '') or 'unknown'
    try:
        trusted = int(os.environ.get('TRUSTED_PROXY_COUNT', getattr(settings, 'TRUSTED_PROXY_COUNT', 0)) or 0)
    except ValueError:
        trusted = 0
    if trusted > 0:
        forwarded = [p.strip() for p in request.META.get('HTTP_X_FORWARDED_FOR', '').split(',') if p.strip()]
        if len(forwarded) >= trusted:
            return forwarded[-trusted]
    return remote


def _key(scope: str, ident: str, window_start: int) -> str:
    digest = hashlib.sha256(f"{scope}:{ident}".encode('utf-8')).hexdigest()[:32]
    return f"rl:{scope}:{digest}:{window_start}"


def hit(scope: str, ident: str, rate: Optional[Tuple[int, int]] = None) -> Tuple[bool, int]:
    """Register one hit. Returns (allowed, retry_after_seconds)."""
    if not rate_limiting_enabled():
        return True, 0
    limit, window = rate or get_rate(scope)
    now = int(time.time())
    window_start = now - (now % window)
    key = _key(scope, ident, window_start)
    cache = caches[getattr(settings, 'RATELIMIT_CACHE_ALIAS', 'default')]
    try:
        if cache.add(key, 1, timeout=window + 5):
            count = 1
        else:
            try:
                count = cache.incr(key)
            except ValueError:
                cache.set(key, 1, timeout=window + 5)
                count = 1
    except Exception as exc:  # cache outage must not disable authentication flows
        logger.error("rate limiter backend failure for scope=%s: %s", scope, type(exc).__name__)
        return True, 0
    if count > limit:
        return False, max(1, window_start + window - now)
    return True, 0


def peek_exceeded(scope: str, ident: str) -> bool:
    """True if the identifier already exceeded the scope limit (no hit recorded)."""
    if not rate_limiting_enabled():
        return False
    limit, window = get_rate(scope)
    now = int(time.time())
    key = _key(scope, ident, now - (now % window))
    try:
        return (caches[getattr(settings, 'RATELIMIT_CACHE_ALIAS', 'default')].get(key) or 0) >= limit
    except Exception:
        return False
