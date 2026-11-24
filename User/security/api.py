"""
JSON API authentication / authorization helpers.

* ``api_login_required``  - session authentication; CSRF is enforced by Django's
  CsrfViewMiddleware for unsafe methods (no csrf_exempt is used for session APIs).
* ``service_token_required`` - explicit bearer-token authentication for external
  worker endpoints. These endpoints are csrf-exempt ONLY because they ignore
  cookies entirely: a request without the service token is rejected even if it
  carries a valid browser session.
* ``api_rate_limited`` - per-user / per-IP request throttling (429).
"""

import functools
import hmac
import json
import logging
import os

from django.http import JsonResponse

from User.security import ratelimit

logger = logging.getLogger(__name__)

MAX_JSON_BODY_BYTES = 64 * 1024


class BadRequest(Exception):
    def __init__(self, message, code='bad_request'):
        self.message = message
        self.code = code
        super().__init__(message)


def json_error(status, code, message, **extra):
    payload = {'success': False, 'error': code, 'message': message}
    payload.update(extra)
    response = JsonResponse(payload, status=status)
    if status == 429 and 'retry_after' in extra:
        response['Retry-After'] = str(extra['retry_after'])
    return response


def parse_json_body(request, max_bytes=MAX_JSON_BODY_BYTES):
    content_type = (request.META.get('CONTENT_TYPE') or '').split(';')[0].strip().lower()
    if content_type != 'application/json':
        raise BadRequest('Content-Type must be application/json', 'unsupported_media_type')
    body = request.body
    if len(body) > max_bytes:
        raise BadRequest('Request body too large', 'payload_too_large')
    try:
        data = json.loads(body.decode('utf-8'))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise BadRequest('Request body must be valid JSON', 'invalid_json')
    if not isinstance(data, dict):
        raise BadRequest('Request body must be a JSON object', 'invalid_json')
    return data


def api_login_required(view):
    @functools.wraps(view)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return json_error(401, 'authentication_required', 'Authentication required')
        return view(request, *args, **kwargs)
    return wrapper


def api_permission_required(*perms):
    def decorator(view):
        @functools.wraps(view)
        def wrapper(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return json_error(401, 'authentication_required', 'Authentication required')
            if not (request.user.is_superuser or request.user.has_perms(perms)):
                return json_error(403, 'forbidden', 'You do not have permission to perform this action')
            return view(request, *args, **kwargs)
        return wrapper
    return decorator


def _configured_service_token():
    token = os.environ.get('FALLBACK_SERVICE_TOKEN', '').strip()
    return token if len(token) >= 32 else ''


def service_token_required(view):
    @functools.wraps(view)
    def wrapper(request, *args, **kwargs):
        expected = _configured_service_token()
        if not expected:
            return json_error(503, 'service_api_disabled',
                              'External worker API is disabled (FALLBACK_SERVICE_TOKEN not configured)')
        header = request.META.get('HTTP_AUTHORIZATION', '')
        scheme, _, provided = header.partition(' ')
        if scheme.lower() != 'bearer' or not provided:
            return json_error(401, 'service_authentication_required', 'Service token required')
        if not hmac.compare_digest(provided.strip().encode(), expected.encode()):
            logger.warning("rejected service API call with invalid token")
            return json_error(403, 'invalid_service_token', 'Invalid service token')
        request.service_authenticated = True
        return view(request, *args, **kwargs)
    return wrapper


def api_rate_limited(scope='api'):
    def decorator(view):
        @functools.wraps(view)
        def wrapper(request, *args, **kwargs):
            ident = f"user:{request.user.id}" if request.user.is_authenticated else f"ip:{ratelimit.client_ip(request)}"
            allowed, retry_after = ratelimit.hit(scope, ident)
            if not allowed:
                return json_error(429, 'rate_limited', 'Too many requests', retry_after=retry_after)
            return view(request, *args, **kwargs)
        return wrapper
    return decorator
