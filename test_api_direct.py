import os
import django
import json
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'MaliciousBot.settings')
django.setup()

from django.http import HttpRequest
from User.models import Domain, URL, Scan, Prediction, ThreatIndicator, ScanIndicator
from User.api import (
    fallback_result, uncertain_scans, scan_status,
    domain_correlation, malicious_ips
)
from User.services.fallback_service import FallbackIntegrationService

print("=" * 60)
print("TESTING API ENDPOINTS DIRECTLY")
print("=" * 60)

# Test 1: uncertain_scans
print("\n" + "="*60)
print("TEST 1: uncertain_scans()")
print("="*60)

request = HttpRequest()
request.method = 'GET'
response = uncertain_scans(request)
print(f"Status: {response.status_code}")
if response.status_code == 200:
    data = json.loads(response.content)
    print(f"Success: {data.get('success')}")
    print(f"Count: {data.get('count')}")
    print(f"Scans: {json.dumps(data.get('scans', []), indent=2, default=str)}")

# Test 2: scan_status
print("\n" + "="*60)
print("TEST 2: scan_status()")
print("="*60)

from User.models import Scan
uncertain_scan = Scan.objects.filter(status='UNCERTAIN').first()
if uncertain_scan:
    request = HttpRequest()
    request.method = 'GET'
    response = scan_status(request, uncertain_scan.id)
    print(f"Status: {response.status_code}")
    if response.status_code == 200:
        data = json.loads(response.content)
        print(f"Success: {data.get('success')}")
        print(f"Scan: {json.dumps(data.get('scan', {}), indent=2, default=str)}")
else:
    print("No uncertain scans found")

# Test 3: domain_correlation
print("\n" + "="*60)
print("TEST 3: domain_correlation()")
print("="*60)

from User.models import Domain
domain = Domain.objects.first()
if domain:
    request = HttpRequest()
    request.method = 'GET'
    response = domain_correlation(request, domain.id)
    print(f"Status: {response.status_code}")
    if response.status_code == 200:
        data = json.loads(response.content)
        print(f"Success: {data.get('success')}")
        print(f"Domain ID: {data.get('domain_id')}")
        print(f"Data keys: {list(data.get('data', {}).keys())}")

# Test 4: malicious_ips
print("\n" + "="*60)
print("TEST 4: malicious_ips()")
print("="*60)

request = HttpRequest()
request.method = 'GET'
response = malicious_ips(request)
print(f"Status: {response.status_code}")
if response.status_code == 200:
    data = json.loads(response.content)
    print(f"Success: {data.get('success')}")
    print(f"Count: {data.get('count')}")
    print(f"IPs: {json.dumps(data.get('ips', []), indent=2, default=str)}")

# Test 5: POST /api/fallback/result/
print("\n" + "="*60)
print("TEST 5: POST /api/fallback/result/")
print("="*60)

from User.models import Scan
uncertain_scan = Scan.objects.filter(status='UNCERTAIN').first()
if uncertain_scan:
    payload = {
        'scan_id': uncertain_scan.id,
        'analysis_status': 'COMPLETED',
        'final_classification': 'Malware',
        'risk_level': 'CRITICAL',
        'risk_score': 0.98,
        'evidence_summary': 'Deep analysis confirmed malicious behavior',
        'threat_indicators': ['SHORTENER:bit.ly', 'IP_ADDRESS:10.0.0.1'],
        'mongo_document_reference': 'mongo_doc_123'
    }
    
    request = HttpRequest()
    request.method = 'POST'
    request._body = json.dumps(payload).encode('utf-8')
    request.META['CONTENT_TYPE'] = 'application/json'
    
    from User.api import fallback_result
    response = fallback_result(request)
    print(f"Status: {response.status_code}")
    if response.status_code == 200:
        data = json.loads(response.content)
        print(f"Success: {data.get('success')}")
        print(f"Message: {data.get('message')}")
else:
    print("No uncertain scans found")

print("\n" + "="*60)
print("ALL DIRECT API TESTS COMPLETED")
print("="*60)