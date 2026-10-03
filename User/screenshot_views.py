import re
from pathlib import Path

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.http import FileResponse, Http404


_SCREENSHOT_NAME = re.compile(r"^scan_(\d+)_\d+\.png$")


@login_required
def serve_screenshot(request, filename):
    """Serve a captured screenshot only to the user who owns its scan."""
    match = _SCREENSHOT_NAME.fullmatch(filename)
    if not match:
        raise Http404("Invalid screenshot name")

    scan_id = int(match.group(1))
    from User.models import Scan

    if not Scan.objects.filter(pk=scan_id, user_id=request.user.id).exists():
        raise Http404("Screenshot not found")

    media_root = Path(
        getattr(settings, "MEDIA_ROOT", Path(settings.BASE_DIR) / "media")
    ).resolve()
    screenshots_root = (media_root / "screenshots").resolve()
    screenshot_path = (screenshots_root / filename).resolve()

    try:
        screenshot_path.relative_to(screenshots_root)
    except ValueError:
        raise Http404("Screenshot not found")

    if not screenshot_path.is_file():
        raise Http404("Screenshot not found")

    return FileResponse(screenshot_path.open("rb"), content_type="image/png")
