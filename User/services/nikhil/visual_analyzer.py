import os
import time
import logging

from django.conf import settings

from User.security import outbound
from User.security.tenancy import is_valid_tenant_id, storage_key
from User.services.domain_normalization import ensure_scheme

logger = logging.getLogger(__name__)


class VisualAnalyzer:
    """
    Service for visual inspection and screenshot evidence collection.
    Produces EVIDENCE ONLY. Does not classify URLs independently.

    Phase 1 controlled-egress design
    --------------------------------
    The browser is never allowed to open network connections itself:

    * Chromium is launched with a black-hole proxy (``127.0.0.1:9``, with the
      implicit loopback bypass removed) and DNS prefetch / background networking
      disabled, so any request escaping interception fails.
    * Every request is intercepted (``context.route('**/*')``). Only GET/HEAD
      document/sub-resource requests are considered; each URL is validated by
      ``User.security.outbound`` and fetched by the DNS-pinned transport, then
      handed to the browser with ``route.fulfill``. DNS rebinding therefore
      cannot redirect the browser to an internal address.
    * JavaScript, downloads, service workers and permissions are disabled; TLS
      errors are NOT ignored (TLS is verified by the pinned transport).
    * Screenshots are stored under a tenant directory using the scan's
      globally unique investigation id and capped at SCREENSHOT_MAX_BYTES.

    Residual risk: Chromium runs with ``--no-sandbox`` on Render (no user
    namespaces). Set VISUAL_ANALYSIS_ENABLED=false to disable live browser
    analysis entirely. If Playwright is unavailable the result is UNAVAILABLE
    (never a fake success).
    """

    NAVIGATION_TIMEOUT_MS = 8000   # 8 seconds
    TOTAL_TIMEOUT_MS = 12000       # 12 seconds
    MAX_SUBRESOURCES = 40
    MAX_RESOURCE_BYTES = 2 * 1024 * 1024
    BLACKHOLE_PROXY = 'http://127.0.0.1:9'
    USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) PhishScan/1.0"
    BLOCKED_RESOURCE_TYPES = frozenset({'websocket', 'eventsource', 'manifest', 'ping', 'texttrack', 'media'})
    BROWSER_ARGS = (
        "--no-sandbox",
        "--disable-setuid-sandbox",
        "--disable-dev-shm-usage",
        "--disable-gpu",
        "--disable-local-storage",
        "--dns-prefetch-disable",
        "--disable-background-networking",
        "--disable-component-update",
        "--disable-default-apps",
        "--disable-extensions",
        "--disable-sync",
        "--no-first-run",
        "--no-pings",
    )

    @staticmethod
    def screenshots_root():
        return os.path.join(getattr(settings, 'MEDIA_ROOT', os.path.join(settings.BASE_DIR, 'media')), 'screenshots')

    @classmethod
    def screenshot_location(cls, tenant_id, investigation_id):
        """(absolute_path, public_reference) for a tenant-scoped screenshot."""
        inv = str(investigation_id).replace('-', '').lower()
        if len(inv) != 32 or not all(c in '0123456789abcdef' for c in inv):
            raise ValueError('investigation_id must be a UUID')
        directory = os.path.join(cls.screenshots_root(), storage_key(tenant_id))
        return os.path.join(directory, f"{inv}.png"), f"/media/screenshots/{inv}.png"

    @classmethod
    def _base_evidence(cls, url):
        return {
            "status": "PENDING",
            "url": url,
            "screenshot_reference": None,
            "title": "",
            "visual_metadata": {},
            "visual_findings": [],
            "security_block": None,
            "error": None,
            "timestamp": time.time(),
        }

    @classmethod
    def analyze_visual(cls, url, scan_id=None, tenant_id=None, investigation_id=None):
        evidence = cls._base_evidence(url)

        if not getattr(settings, 'VISUAL_ANALYSIS_ENABLED', True):
            evidence["status"] = "UNAVAILABLE"
            evidence["error"] = "Visual analysis disabled by configuration (VISUAL_ANALYSIS_ENABLED=false)"
            evidence["visual_findings"].append("Visual analysis disabled")
            return evidence

        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            evidence["status"] = "UNAVAILABLE"
            evidence["error"] = "Playwright browser automation not installed"
            evidence["visual_findings"].append("Visual analysis unavailable: Playwright not installed")
            return evidence

        if not is_valid_tenant_id(tenant_id) or not investigation_id:
            evidence["status"] = "UNAVAILABLE"
            evidence["error"] = "Visual analysis requires a server-side tenant and investigation identity"
            return evidence

        target_url = ensure_scheme(url)
        try:
            outbound.validate_url(target_url)
        except outbound.OutboundBlocked as blocked:
            evidence["status"] = "BLOCKED"
            evidence["security_block"] = blocked.reason
            evidence["error"] = f"Destination blocked by outbound security policy: {blocked.reason}"
            return evidence
        except outbound.OutboundError as err:
            evidence["status"] = "UNAVAILABLE"
            evidence["error"] = f"Destination could not be validated: {err.reason}"
            return evidence

        path, reference = cls.screenshot_location(tenant_id, investigation_id)
        stats = {"fulfilled": 0, "blocked": 0, "failed": 0}

        def handle_route(route, request):
            try:
                if request.method not in ('GET', 'HEAD') or request.resource_type in cls.BLOCKED_RESOURCE_TYPES:
                    stats["blocked"] += 1
                    return route.abort('blockedbyclient')
                if stats["fulfilled"] >= cls.MAX_SUBRESOURCES:
                    stats["blocked"] += 1
                    return route.abort('blockedbyclient')
                try:
                    resp = outbound.safe_request(
                        request.url, method=request.method,
                        headers={"User-Agent": cls.USER_AGENT, "Accept": request.headers.get('accept', '*/*')},
                        max_bytes=cls.MAX_RESOURCE_BYTES, max_redirects=3, total_timeout=6.0)
                except outbound.OutboundBlocked:
                    stats["blocked"] += 1
                    return route.abort('blockedbyclient')
                except outbound.OutboundError:
                    stats["failed"] += 1
                    return route.abort('failed')
                stats["fulfilled"] += 1
                content_type = next((v for k, v in resp.headers.items() if k.lower() == 'content-type'),
                                    'application/octet-stream')
                return route.fulfill(status=resp.status, headers={'Content-Type': content_type}, body=resp.body)
            except Exception:
                stats["failed"] += 1
                try:
                    return route.abort('failed')
                except Exception:
                    return None

        browser = None
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True, args=list(cls.BROWSER_ARGS),
                                            proxy={"server": cls.BLACKHOLE_PROXY, "bypass": "<-loopback>"})
                context = browser.new_context(
                    viewport={"width": 1280, "height": 800},
                    java_script_enabled=False,
                    accept_downloads=False,
                    service_workers='block',
                    ignore_https_errors=False,
                    permissions=[],
                    user_agent=cls.USER_AGENT,
                )
                context.route('**/*', handle_route)
                page = context.new_page()
                page.set_default_navigation_timeout(cls.NAVIGATION_TIMEOUT_MS)
                page.set_default_timeout(cls.TOTAL_TIMEOUT_MS)
                page.goto(target_url, wait_until="domcontentloaded")
                evidence["title"] = (page.title() or '')[:300]

                os.makedirs(os.path.dirname(path), exist_ok=True)
                page.screenshot(path=path, full_page=False)
                browser.close()
                browser = None

            size = os.path.getsize(path) if os.path.exists(path) else 0
            max_bytes = getattr(settings, 'SCREENSHOT_MAX_BYTES', 5 * 1024 * 1024)
            if size == 0 or size > max_bytes:
                if os.path.exists(path):
                    os.remove(path)
                evidence["status"] = "UNAVAILABLE"
                evidence["error"] = "Screenshot rejected: empty or exceeds size limit"
                return evidence

            evidence["screenshot_reference"] = reference
            evidence["status"] = "SUCCESS"
            evidence["visual_metadata"] = {
                "viewport": {"width": 1280, "height": 800},
                "file_size_bytes": size,
                "requests_fulfilled": stats["fulfilled"],
                "requests_blocked": stats["blocked"],
                "requests_failed": stats["failed"],
                "egress": "controlled (pinned transport via route.fulfill; black-hole proxy)",
            }
            evidence["visual_findings"].append("Screenshot captured with controlled egress")
        except Exception as e:
            logger.warning("Visual analysis failed: %s", type(e).__name__)
            evidence["status"] = "UNAVAILABLE"
            evidence["error"] = f"Browser automation execution failed: {type(e).__name__}"
            evidence["visual_findings"].append("Visual capture error")
        finally:
            if browser is not None:
                try:
                    browser.close()
                except Exception:
                    pass
        return evidence

    @classmethod
    def analyze_fixture(cls, fixture_name, title="Fixture Page", findings=None):
        """Helper for test fixtures where controlled visual metadata is provided"""
        return {
            "status": "SUCCESS",
            "screenshot_reference": f"/media/screenshots/{fixture_name}.png",
            "title": title,
            "visual_metadata": {"viewport": {"width": 1280, "height": 800}, "fixture": True},
            "visual_findings": findings or ["Rendered visual layout verified from fixture"]
        }
