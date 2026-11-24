"""
JSON API endpoints (Phase 1 hardened).

Authentication model
--------------------
* Browser APIs (scan status, investigation detail, correlation, review): Django
  session authentication + CSRF for unsafe methods (no ``csrf_exempt``). Every
  query runs against the caller's own tenant database (``request.user_db``) and
  scan ownership (``Scan.user_id == request.user.id``) is verified.
* Worker API (``POST /api/fallback/result/``): service-token authentication
  (``Authorization: Bearer $FALLBACK_SERVICE_TOKEN``). It is csrf-exempt only
  because it never uses cookies -- a request without the token is rejected even
  if it carries a valid browser session. The tenant is resolved server-side
  from the registry and the scan's ``investigation_id`` must match.
* Internal error details are never returned to clients.
"""

import logging
import uuid

from django.db import transaction
from django.http import JsonResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from User.models import AnalystReview, Scan, ScanFinalDecision
from User.security.api import (
    BadRequest, api_login_required, api_permission_required, api_rate_limited, json_error,
    parse_json_body, service_token_required,
)
from User.security.tenancy import is_valid_tenant_id, resolve_existing_tenant_alias, tenant_id_for_user
from User.services.correlation_service import CorrelationService
from User.services.fallback_service import FallbackIntegrationService

logger = logging.getLogger(__name__)

REVIEW_LABELS = frozenset(choice for choice, _ in AnalystReview.VALIDATION_CHOICES)
REVIEW_VALIDATION_STATUSES = frozenset(choice for choice, _ in AnalystReview.VALIDATED_CHOICES)
CONCRETE_CLASSES = frozenset({'Benign', 'Phishing', 'Malware', 'Defacement'})
MAX_REVIEW_NOTES = 5000


def _user_alias(request):
    return getattr(request, 'user_db', None) or 'guest_db'


def _owned_scan(request, scan_id):
    """Return the caller's scan from their own tenant DB, or None."""
    return (Scan.objects.using(_user_alias(request))
            .select_related('url').filter(id=scan_id, user_id=request.user.id).first())


@require_http_methods(["POST"])
@api_permission_required('User.submit_review')
@api_rate_limited('review')
def submit_review(request):
    """
    Analyst review for a scan in the analyst's own tenant database.

    * Requires the ``User.submit_review`` permission (Analyst group) or superuser.
    * Labels / statuses are validated against the model choices.
    * A concrete label updates the authoritative final decision ONLY when that
      decision is NEEDS_REVIEW (or already OVERRIDDEN); overriding a FINAL or
      CONFIDENT_ML decision additionally requires ``User.override_final_decision``.
    """
    try:
        data = parse_json_body(request)
    except BadRequest as exc:
        return json_error(415 if exc.code == 'unsupported_media_type' else 400, exc.code, exc.message)

    scan_id = data.get('scan_id')
    final_label = data.get('final_label')
    review_notes = data.get('review_notes', '') or ''
    validation_status = data.get('validation_status', 'NOT_VALIDATED')

    if not isinstance(scan_id, int) or isinstance(scan_id, bool) or scan_id <= 0:
        return json_error(400, 'invalid_scan_id', 'scan_id must be a positive integer')
    if final_label not in REVIEW_LABELS:
        return json_error(400, 'invalid_label', f"final_label must be one of {sorted(REVIEW_LABELS)}")
    if validation_status not in REVIEW_VALIDATION_STATUSES:
        return json_error(400, 'invalid_validation_status',
                          f"validation_status must be one of {sorted(REVIEW_VALIDATION_STATUSES)}")
    if not isinstance(review_notes, str) or len(review_notes) > MAX_REVIEW_NOTES:
        return json_error(400, 'invalid_notes', f"review_notes must be a string of at most {MAX_REVIEW_NOTES} characters")

    alias = _user_alias(request)
    try:
        with transaction.atomic(using=alias):
            scan = Scan.objects.using(alias).select_for_update().filter(id=scan_id).first()
            if scan is None:
                return json_error(404, 'not_found', 'Scan not found')
            decision = ScanFinalDecision.objects.using(alias).filter(scan=scan).first()
            overrides = final_label in CONCRETE_CLASSES and decision is not None
            if overrides and decision.decision_status not in ('NEEDS_REVIEW', 'OVERRIDDEN'):
                if not (request.user.is_superuser or request.user.has_perm('User.override_final_decision')):
                    return json_error(403, 'decision_locked',
                                      'This scan has an authoritative final decision; overriding it requires '
                                      'the override_final_decision permission')

            review, created = AnalystReview.objects.using(alias).update_or_create(
                scan=scan,
                defaults={
                    'reviewer': request.user,
                    'final_label': final_label,
                    'review_notes': review_notes,
                    'validation_status': validation_status,
                    'reviewed_at': timezone.now(),
                },
            )
            decision_updated = False
            if overrides:
                original = f"{decision.final_classification}/{decision.decision_status}"
                decision.final_classification = final_label
                decision.decision_status = 'OVERRIDDEN'
                decision.decision_method = 'ANALYST_REVIEW'
                decision.decision_summary = (f"Analyst review by user {request.user.id} set {final_label} "
                                             f"(was {original}).")[:500]
                decision.save(using=alias)
                decision_updated = True
    except Exception as exc:
        logger.error("review submission failed: %s", type(exc).__name__)
        return json_error(500, 'internal_error', 'Review could not be saved')

    return JsonResponse({
        'success': True,
        'message': f'Review submitted for Scan {scan_id}',
        'review_id': review.id,
        'created': created,
        'final_decision_updated': decision_updated,
    })


@require_http_methods(["GET"])
@api_login_required
@api_rate_limited('api')
def investigation_detail(request, scan_id):
    """Forensic evidence for one of the caller's own scans (tenant-scoped Mongo lookup)."""
    scan = _owned_scan(request, scan_id)
    if scan is None:
        return json_error(404, 'not_found', 'Scan not found')
    try:
        from User.services.nikhil.mongodb_repository import MongoDBRepository
        evidence = MongoDBRepository().get_evidence(scan.id, tenant_id=tenant_id_for_user(request.user))
        prediction = getattr(scan, 'prediction', None) if hasattr(scan, 'prediction') else None
        return JsonResponse({
            'success': True,
            'scan_id': scan.id,
            'investigation_id': str(scan.investigation_id),
            'url': scan.url.url,
            'status': scan.status,
            'forensic_status': scan.forensic_status,
            'initial_prediction': {
                'predicted_class': prediction.predicted_class if prediction else None,
                'confidence': prediction.confidence if prediction else None,
            },
            'deep_analysis_evidence': evidence,
        }, json_dumps_params={'default': str})
    except Exception as exc:
        logger.error("investigation detail failed for scan %s: %s", scan_id, type(exc).__name__)
        return json_error(500, 'internal_error', 'Investigation details are unavailable')


@csrf_exempt  # token-only endpoint: cookies/sessions are never accepted (see module docstring)
@require_http_methods(["POST"])
@service_token_required
def fallback_result(request):
    """External fallback worker submits a result for a scan in a specific tenant."""
    try:
        data = parse_json_body(request, max_bytes=512 * 1024)
    except BadRequest as exc:
        return json_error(415 if exc.code == 'unsupported_media_type' else 400, exc.code, exc.message)

    tenant_id = data.get('tenant_id')
    investigation_id = data.get('investigation_id')
    if not is_valid_tenant_id(tenant_id):
        return json_error(400, 'invalid_tenant', "tenant_id must be 'guest' or 'user:<id>'")
    try:
        uuid.UUID(str(investigation_id))
    except (ValueError, TypeError):
        return json_error(400, 'invalid_investigation_id', 'investigation_id (UUID) is required')
    alias = resolve_existing_tenant_alias(tenant_id)
    if alias is None:
        return json_error(404, 'not_found', 'Scan not found')
    if not Scan.objects.using(alias).filter(id=data.get('scan_id') if isinstance(data.get('scan_id'), int) else -1,
                                            investigation_id=investigation_id).exists():
        return json_error(404, 'not_found', 'Scan not found')

    result = FallbackIntegrationService.process_fallback_result(data, db_alias=alias, tenant_id=tenant_id)
    if result.get('success'):
        return JsonResponse(result, status=200)
    status_code = 409 if result.get('message') == 'Invalid scan state' else 400
    if result.get('message', '').startswith('Fallback persistence failed'):
        status_code = 500
    return JsonResponse({'success': False, 'scan_id': result.get('scan_id'), 'message': result.get('message'),
                         'errors': result.get('errors')}, status=status_code)


@require_http_methods(["GET"])
@api_login_required
@api_rate_limited('api')
def uncertain_scans(request):
    """The caller's own scans that are still awaiting / undergoing deep analysis."""
    try:
        scans = FallbackIntegrationService.get_uncertain_scans(limit=20, db=_user_alias(request),
                                                               user_id=request.user.id)
        scan_list = []
        for scan in scans:
            pred = getattr(scan, 'prediction', None) if hasattr(scan, 'prediction') else None
            scan_list.append({
                'scan_id': scan.id,
                'investigation_id': str(scan.investigation_id),
                'url': scan.url.url if scan.url else None,
                'status': scan.status,
                'created_at': scan.created_at.isoformat() if scan.created_at else None,
                'initial_prediction': {
                    'predicted_class': pred.predicted_class if pred else None,
                    'confidence': pred.confidence if pred else None,
                    'risk_score': pred.risk_score if pred else None,
                },
            })
        return JsonResponse({'success': True, 'count': len(scan_list), 'scans': scan_list})
    except Exception as exc:
        logger.error("uncertain scans listing failed: %s", type(exc).__name__)
        return json_error(500, 'internal_error', 'Scan list unavailable')


@require_http_methods(["GET"])
@api_login_required
@api_rate_limited('api')
def scan_status(request, scan_id):
    try:
        status_data = FallbackIntegrationService.get_scan_status(scan_id, db=_user_alias(request),
                                                                 user_id=request.user.id)
    except Exception as exc:
        logger.error("scan status failed for scan %s: %s", scan_id, type(exc).__name__)
        return json_error(500, 'internal_error', 'Scan status unavailable')
    if status_data is None:
        return json_error(404, 'not_found', 'Scan not found')
    return JsonResponse({'success': True, 'scan': status_data})


@require_http_methods(["GET"])
@api_login_required
@api_rate_limited('api')
def domain_correlation(request, domain_id):
    """Correlation data for a domain in the caller's own tenant database."""
    from User.models import Domain
    alias = _user_alias(request)
    if not Domain.objects.using(alias).filter(id=domain_id).exists():
        return json_error(404, 'not_found', 'Domain not found')
    try:
        data = CorrelationService.get_related_security_data(domain_id, db=alias)
        return JsonResponse({'success': True, 'domain_id': domain_id, 'data': data},
                            json_dumps_params={'default': str})
    except Exception as exc:
        logger.error("domain correlation failed for domain %s: %s", domain_id, type(exc).__name__)
        return json_error(500, 'internal_error', 'Correlation data unavailable')


@require_http_methods(["GET"])
@api_login_required
@api_rate_limited('api')
def malicious_ips(request):
    """IPs linked to malicious scan outcomes in the caller's own tenant database."""
    alias = _user_alias(request)
    try:
        ips = CorrelationService.get_ips_by_malicious_urls(limit=20, db=alias)
        ip_list = []
        for ip in ips:
            ip_list.append({
                'ip_id': ip.id,
                'ip_address': ip.ip_address,
                'status': ip.status,
                'country': ip.country,
                'risk_score': ip.risk_score,
                'malicious_url_count': ip.malicious_count,
                'domain_count': ip.domain_count,
                'domains': list(CorrelationService.get_domains_by_ip(ip.id, db=alias)
                                .values_list('domain_name', flat=True)[:10]),
            })
        return JsonResponse({'success': True, 'count': len(ip_list), 'ips': ip_list})
    except Exception as exc:
        logger.error("malicious IP correlation failed: %s", type(exc).__name__)
        return json_error(500, 'internal_error', 'Correlation data unavailable')
