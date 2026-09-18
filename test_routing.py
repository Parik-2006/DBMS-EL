import os
import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'MaliciousBot.settings')
django.setup()

from django.contrib.auth.models import User
from User.models import Domain, URL, Scan, Prediction
from User.services import get_confidence_threshold, set_confidence_threshold
from User.services.ml_service import MLPredictionService
from User.services.correlation_service import CorrelationService

print("=" * 60)
print("TESTING CONFIDENCE ROUTING")
print("=" * 60)

# Test threshold
threshold = get_confidence_threshold()
print(f"\nCurrent confidence threshold: {threshold}")

# Create test user
user = User.objects.first()
if not user:
    user = User.objects.create_user(username='testuser', password='test123')
    print("Created test user")
else:
    print(f"Using existing user: {user.username}")

# Create test URL in DB
domain, _ = Domain.objects.get_or_create(domain_name='test-example.com', defaults={'tld': '.com'})
url_obj, _ = URL.objects.get_or_create(url='https://test-example.com/page1', defaults={'domain': domain, 'source': 'USER_SCAN'})

print(f"\nTest URL object: {url_obj}")

# Test 1: High confidence (should be CONFIDENT)
print("\n" + "="*50)
print("TEST 1: HIGH CONFIDENCE PREDICTION")
print("="*50)

scan1 = MLPredictionService.create_scan_record(url_obj, user)
print(f"Created scan: {scan1.id}")

# Manually create high confidence prediction
pred1 = Prediction.objects.create(
    scan=scan1,
    model_name='RandomForest',
    predicted_class='Benign',
    confidence=0.95,
    risk_score=0.05,
    probabilities={'Benign': 0.95, 'Phishing': 0.03, 'Malware': 0.02, 'Defacement': 0.0}
)

# Update scan status
scan1.status = 'CONFIDENT'
scan1.save()

print(f"Scan status: {scan1.status}")
print(f"Prediction: {pred1.predicted_class}, Confidence: {pred1.confidence}")
print(f"Is confident: {pred1.confidence >= get_confidence_threshold()}")

# Test 2: Low confidence (should be UNCERTAIN)
print("\n" + "="*50)
print("TEST 2: LOW CONFIDENCE PREDICTION")
print("="*50)

scan2 = MLPredictionService.create_scan_record(url_obj, user)
print(f"Created scan: {scan2.id}")

pred2 = Prediction.objects.create(
    scan=scan2,
    model_name='RandomForest',
    predicted_class='Phishing',
    confidence=0.62,
    risk_score=0.62,
    probabilities={'Benign': 0.20, 'Phishing': 0.62, 'Malware': 0.15, 'Defacement': 0.03}
)

scan2.status = 'UNCERTAIN'
scan2.save()

print(f"Scan status: {scan2.status}")
print(f"Prediction: {pred2.predicted_class}, Confidence: {pred2.confidence}")
print(f"Is confident: {pred2.confidence >= get_confidence_threshold()}")

# Test 3: Fallback handoff contract
print("\n" + "="*50)
print("TEST 3: FALLBACK HANDOFF CONTRACT")
print("="*50)

handoff = MLPredictionService.create_fallback_handoff(scan2)
print(f"Handoff contract:")
for k, v in handoff.items():
    print(f"  {k}: {v}")

# Test 4: Correlation queries
print("\n" + "="*50)
print("TEST 4: CORRELATION QUERIES")
print("="*50)

# Get domain with URLs
domain = Domain.objects.get(domain_name='mp3raid.com')
urls = CorrelationService.get_urls_by_domain(domain.id)
print(f"\nURLs for domain 'mp3raid.com': {len(urls)}")
for u in urls[:3]:
    print(f"  {u.url} (source: {u.source})")

# Get domain scan history
domain2 = Domain.objects.get(domain_name='mp3raid.com')
scans = CorrelationService.get_domain_scan_history(domain2.id)
print(f"\nScan history for 'mp3raid.com': {len(scans)} scans")

# Get malicious IPs (should be empty initially - IP model doesn't have direct scan relation)
print("\nSkipping get_ips_by_malicious_urls (IP model needs scan relation)")

# Test 5: Threat indicators
print("\n" + "="*50)
print("TEST 5: THREAT INDICATORS")
print("="*50)

from User.models import ThreatIndicator, ScanIndicator
from User.services.fallback_service import FallbackIntegrationService

# Create some threat indicators (use get_or_create to avoid duplicates)
ti1, _ = ThreatIndicator.objects.get_or_create(
    indicator_type='SHORTENER', 
    indicator_value='bit.ly', 
    defaults={'severity': 'MEDIUM'}
)
ti2, _ = ThreatIndicator.objects.get_or_create(
    indicator_type='DOMAIN', 
    indicator_value='malicious.ru', 
    defaults={'severity': 'HIGH'}
)
ti3, _ = ThreatIndicator.objects.get_or_create(
    indicator_type='IP_ADDRESS', 
    indicator_value='192.168.1.100', 
    defaults={'severity': 'CRITICAL'}
)

print(f"Created/Retrieved threat indicators: {ti1}, {ti2}, {ti3}")

# Get domain threat indicators
domain3 = Domain.objects.get(domain_name='mp3raid.com')
indicators = CorrelationService.get_domain_threat_indicators(domain3.id)
print(f"Threat indicators for mp3raid.com: {len(indicators)}")

# Test fallback validation
print("\n" + "="*50)
print("TEST 5: FALLBACK VALIDATION")
print("="*50)

# Valid fallback result
valid_result = {
    'scan_id': scan2.id,
    'analysis_status': 'COMPLETED',
    'final_classification': 'Malware',
    'risk_level': 'CRITICAL',
    'risk_score': 0.95,
    'evidence_summary': 'Deep analysis found malicious payload',
    'threat_indicators': ['SHORTENER:bit.ly', 'IP_ADDRESS:192.168.1.100'],
    'mongo_document_reference': 'mock_doc_id_123'
}

is_valid, errors = FallbackIntegrationService.validate_fallback_result(valid_result)
print(f"Valid result: {is_valid}, errors: {errors}")

# Invalid result (bad classification)
invalid_result = valid_result.copy()
invalid_result['final_classification'] = 'InvalidClass'
is_valid2, errors2 = FallbackIntegrationService.validate_fallback_result(invalid_result)
print(f"Invalid result: {is_valid2}, errors: {errors2}")

# Test fallback processing
print("\n" + "="*50)
print("TEST 6: FALLBACK PROCESSING")
print("="*50)

result = FallbackIntegrationService.process_fallback_result(valid_result)
print(f"Processing result: {result}")

# Verify scan was updated
scan2.refresh_from_db()
print(f"Scan status after fallback: {scan2.status}")
print(f"Scan fallback_model: {scan2.fallback_model}")

# Check prediction updated
pred2.refresh_from_db()
print(f"Prediction updated: {pred2.predicted_class}, risk_score: {pred2.risk_score}")

# Check threat indicators linked
scan_indicators = ScanIndicator.objects.filter(scan=scan2)
print(f"Threat indicators linked to scan: {scan_indicators.count()}")

# Test 7: Domain aggregate risk
print("\n" + "="*50)
print("TEST 7: DOMAIN AGGREGATE RISK")
print("="*50)

# Create a domain with scans
domain = Domain.objects.get(domain_name='test-example.com')
agg_risk = CorrelationService.calculate_domain_aggregate_risk(domain.id)
print(f"Aggregate risk for test-example.com: {agg_risk}")

# Test comprehensive related data
related = CorrelationService.get_related_security_data(domain.id)
print(f"\nComprehensive data keys: {list(related.keys())}")

# Test prediction changes
changes = CorrelationService.get_domain_prediction_changes(domain.id)
print(f"\nPrediction changes for domain: {len(changes)}")

print("\n" + "="*60)
print("ALL TESTS COMPLETED SUCCESSFULLY!")
print("="*60)