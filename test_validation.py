import os
import django
import json

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'MaliciousBot.settings')
django.setup()

from User.services.fallback_service import FallbackIntegrationService

# Test the validation directly
payload = {
    "scan_id": 8,
    "analysis_status": "COMPLETED",
    "final_classification": "Phishing",
    "risk_level": "MEDIUM",
    "risk_score": 0.5,
    "evidence_summary": "Test",
    "threat_indicators": [],
    "mongo_document_reference": "test123"
}

print("Testing Validation:")
print(json.dumps(payload, indent=2))

valid, errors = FallbackIntegrationService.validate_fallback_result(payload)
print(f"\nValid: {valid}")
print(f"Errors: {errors}")

if valid:
    print("\nAttempting to process...")
    result = FallbackIntegrationService.process_fallback_result(payload)
    print(json.dumps(result, indent=2, default=str))
