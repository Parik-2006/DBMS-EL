"""
Security-header middleware.

Adds a Content-Security-Policy compatible with the existing templates (which use
inline <style>/<script> blocks and inline event handlers, plus Google Fonts,
cdnjs and the Bootstrap CDN for icon fonts), and a restrictive
Permissions-Policy. The CSP can be overridden with the ``CONTENT_SECURITY_POLICY``
setting / env var; set it to an empty string to disable the header.
"""

from django.conf import settings

DEFAULT_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com "
    "https://maxcdn.bootstrapcdn.com; "
    "font-src 'self' data: https://fonts.gstatic.com https://maxcdn.bootstrapcdn.com; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)

DEFAULT_PERMISSIONS_POLICY = (
    "camera=(), microphone=(), geolocation=(), payment=(), usb=(), "
    "accelerometer=(), gyroscope=(), magnetometer=()"
)


class SecurityHeadersMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.csp = getattr(settings, 'CONTENT_SECURITY_POLICY', DEFAULT_CSP)
        self.permissions_policy = getattr(settings, 'PERMISSIONS_POLICY', DEFAULT_PERMISSIONS_POLICY)

    def __call__(self, request):
        response = self.get_response(request)
        if self.csp and 'Content-Security-Policy' not in response:
            response['Content-Security-Policy'] = self.csp
        if self.permissions_policy and 'Permissions-Policy' not in response:
            response['Permissions-Policy'] = self.permissions_policy
        if request.path.startswith('/api/') or request.path.startswith('/media/'):
            response.setdefault('Cache-Control', 'no-store')
        return response
