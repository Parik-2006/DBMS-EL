from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
import json
from User.services.fallback_service import FallbackIntegrationService
from User.services.correlation_service import CorrelationService
from User.models import Scan, AnalystReview
from django.utils import timezone

@csrf_exempt
@require_http_methods(["POST"])
def submit_review(request):
    """
    API endpoint for analysts to submit review for Unknown/Needs Review cases
    """
    try:
        data = json.loads(request.body)
        scan_id = data.get('scan_id')
        final_label = data.get('final_label')
        review_notes = data.get('review_notes', '')
        validation_status = data.get('validation_status', 'NOT_VALIDATED')

        if not scan_id or not final_label:
            return JsonResponse({
                'success': False,
                'message': 'Missing scan_id or final_label'
            }, status=400)

        scan = Scan.objects.get(id=scan_id)
        
        # Create or update review
        review, created = AnalystReview.objects.update_or_create(
            scan=scan,
            defaults={
                'reviewer': request.user if request.user.is_authenticated else None,
                'final_label': final_label,
                'review_notes': review_notes,
                'validation_status': validation_status,
                'reviewed_at': timezone.now()
            }
        )

        return JsonResponse({
            'success': True,
            'message': f'Review submitted for Scan {scan_id}',
            'review_id': review.id
        })

    except Scan.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'Scan not found'}, status=404)
    except Exception as e:
        return JsonResponse({'success': False, 'message': str(e)}, status=500)

@require_http_methods(["GET"])
def investigation_detail(request, scan_id):
    """
    API endpoint to get detailed evidence for investigation
    """
    try:
        from User.services.nikhil.mongodb_repository import MongoDBRepository
        repo = MongoDBRepository()
        
        scan = Scan.objects.get(id=scan_id)
        evidence = repo.get_evidence(scan_id)
        
        return JsonResponse({
            'success': True,
            'scan_id': scan_id,
            'url': scan.url.url,
            'initial_prediction': {
                'predicted_class': scan.prediction.predicted_class if hasattr(scan, 'prediction') else None,
                'confidence': scan.prediction.confidence if hasattr(scan, 'prediction') else None,
            },
            'deep_analysis_evidence': evidence
        })

    except Scan.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'Scan not found'}, status=404)
    except Exception as e:
        return JsonResponse({'success': False, 'message': str(e)}, status=500)

@csrf_exempt
@require_http_methods(["POST"])
def fallback_result(request):
    """
    API endpoint for fallback system to return analysis results
    """
    try:
        # Use simple print for debugging in local env
        data = json.loads(request.body)
        
        result = FallbackIntegrationService.process_fallback_result(data)
        
        # Ensure we return JSON in all cases
        status_code = 200 if result.get('success', False) else 400
        return JsonResponse(result, status=status_code)
    
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'message': 'Invalid JSON in request body',
            'errors': ['Request body must be valid JSON']
        }, status=400)
    except Exception as e:
        # Important: log and return proper JSON error
        return JsonResponse({
            'success': False,
            'message': f'Server error: {str(e)}',
            'errors': [str(e)]
        }, status=500)


@require_http_methods(["GET"])
def uncertain_scans(request):
    """
    Get list of scans awaiting fallback analysis
    
    GET endpoint: /api/fallback/uncertain-scans/
    """
    try:
        scans = FallbackIntegrationService.get_uncertain_scans(limit=20)
        
        scan_list = []
        for scan in scans:
            scan_list.append({
                'scan_id': scan.id,
                'url': scan.url.url if scan.url else None,
                'status': scan.status,
                'created_at': scan.created_at.isoformat() if scan.created_at else None,
                'initial_prediction': {
                    'predicted_class': scan.prediction.predicted_class if scan.prediction else None,
                    'confidence': scan.prediction.confidence if scan.prediction else None,
                    'risk_score': scan.prediction.risk_score if scan.prediction else None
                }
            })
        
        return JsonResponse({
            'success': True,
            'count': len(scan_list),
            'scans': scan_list
        })
    
    except Exception as e:
        return JsonResponse({
            'success': False,
            'message': str(e),
            'errors': [str(e)]
        }, status=500)


@require_http_methods(["GET"])
def scan_status(request, scan_id):
    """
    Get status of a specific scan
    
    GET endpoint: /api/fallback/scan-status/<scan_id>/
    """
    try:
        status_data = FallbackIntegrationService.get_scan_status(scan_id)
        
        if status_data is None:
            return JsonResponse({
                'success': False,
                'message': f'Scan {scan_id} not found'
            }, status=404)
        
        return JsonResponse({
            'success': True,
            'scan': status_data
        })
    
    except Exception as e:
        return JsonResponse({
            'success': False,
            'message': str(e),
            'errors': [str(e)]
        }, status=500)


@require_http_methods(["GET"])
def domain_correlation(request, domain_id):
    """
    Get comprehensive correlation data for a domain
    
    GET endpoint: /api/correlation/domain/<domain_id>/
    """
    try:
        correlation_data = CorrelationService.get_related_security_data(domain_id)
        
        return JsonResponse({
            'success': True,
            'domain_id': domain_id,
            'data': correlation_data
        })
    
    except Exception as e:
        return JsonResponse({
            'success': False,
            'message': str(e),
            'errors': [str(e)]
        }, status=500)


@require_http_methods(["GET"])
def malicious_ips(request):
    """
    Get IPs associated with multiple malicious URLs
    
    GET endpoint: /api/correlation/malicious-ips/
    """
    try:
        ips = CorrelationService.get_ips_by_malicious_urls(limit=20)
        
        ip_list = []
        for ip in ips:
            ip_list.append({
                'ip_id': ip.id,
                'ip_address': ip.ip_address,
                'status': ip.status,
                'country': ip.country,
                'risk_score': ip.risk_score,
                'malicious_url_count': ip.malicious_count
            })
        
        return JsonResponse({
            'success': True,
            'count': len(ip_list),
            'ips': ip_list
        })
    
    except Exception as e:
        return JsonResponse({
            'success': False,
            'message': str(e),
            'errors': [str(e)]
        }, status=500)
