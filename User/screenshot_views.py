import re
import uuid
from pathlib import Path

from django.contrib.auth.decorators import login_required
from django.http import FileResponse, Http404
from django.views.decorators.http import require_GET

from User.security.tenancy import storage_key, tenant_id_for_user

# Phase 1: screenshots are named by the scan's globally unique investigation id
# (32 hex chars). Legacy names (scan_<id>_<ts>.png) collide across tenants and
# are intentionally no longer served.
_SCREENSHOT_NAME = re.compile(r"^([0-9a-f]{32})\.png$")


@require_GET
@login_required
def serve_screenshot(request, filename):
    """Serve a screenshot only to the authenticated owner of the scan."""
    match = _SCREENSHOT_NAME.fullmatch(filename or '')
    if not match:
        raise Http404("Screenshot not found")
    investigation_id = uuid.UUID(match.group(1))

    from User.models import Scan
    from User.services.nikhil.visual_analyzer import VisualAnalyzer

    tenant_id = tenant_id_for_user(request.user)
    alias = getattr(request, 'user_db', None)
    scans = Scan.objects.using(alias) if alias else Scan.objects
    # Ownership: the scan must exist in the caller's own tenant database and
    # belong to the caller.
    if not scans.filter(investigation_id=investigation_id, user_id=request.user.id).exists():
        raise Http404("Screenshot not found")

    root = Path(VisualAnalyzer.screenshots_root()).resolve()
    tenant_root = (root / storage_key(tenant_id)).resolve()
    path = (tenant_root / f"{investigation_id.hex}.png").resolve()
    try:
        path.relative_to(tenant_root)
    except ValueError:
        raise Http404("Screenshot not found")
    if not path.is_file():
        raise Http404("Screenshot not found")

    response = FileResponse(path.open("rb"), content_type="image/png")
    response['X-Content-Type-Options'] = 'nosniff'
    response['Cache-Control'] = 'private, no-store'
    return response
