from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
import json
from User.services.fallback_service import FallbackIntegrationService
from User.services.correlation_service import CorrelationService

@csrf_exempt
@require_http_methods(["POST"])
def fallback_result(request):
    """
    API endpoint for fallback system to return analysis results
    
    POST endpoint: /api/fallback/result/
    
    Expected JSON body:
    {
        "scan_id": int,
        "analysis_status": str,
        "final_classification": str,
        "risk_level": str,
        "risk_score": float,
        "evidence_summary": str,
        "threat_indicators": [str],
        "mongo_document_reference": str (optional)
    }
    """
    try:
        data = json.loads(request.body)
        
        result = FallbackIntegrationService.process_fallback_result(data)
        
        status_code = 200 if result['success'] else 400
        return JsonResponse(result, status=status_code)
    
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'message': 'Invalid JSON in request body',
            'errors': ['Request body must be valid JSON']
        }, status=400)
    except Exception as e:
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
