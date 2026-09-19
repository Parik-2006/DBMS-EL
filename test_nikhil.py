import os
import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'MaliciousBot.settings')
django.setup()

from User.services.nikhil.orchestration_service import FallbackOrchestrator
from User.models import Scan, URL

print("=" * 60)
print("TESTING NIKHIL SERVICES")
print("=" * 60)

# Create a dummy scan for testing
scan = Scan.objects.all().first()
if not scan:
    print("No scans found to test")
    exit()

print(f"\nTesting analysis for Scan {scan.id}, URL: {scan.url.url}")

orchestrator = FallbackOrchestrator()
evidence, mongo_id = orchestrator.perform_deep_analysis(scan.id, scan.url.url)

print(f"\nAnalysis Status: {evidence['analysis_status']}")
print(f"MongoDB Document ID: {mongo_id}")
print(f"Webpage Analysis: {evidence['webpage']['status']}")
print(f"Network Analysis: {evidence['network']['status']}")
print(f"AI Analysis: {evidence['ai_analysis']['status']}")
print(f"Prompt Injection Detected: {evidence['ai_analysis']['prompt_injection_detected']}")

from User.services.nikhil.final_classifier import FinalClassifier
final_result = FinalClassifier.classify(
    scan.prediction.predicted_class if hasattr(scan, 'prediction') else None,
    scan.prediction.confidence if hasattr(scan, 'prediction') else None,
    evidence
)

print(f"\nFinal Result: {final_result}")

print("\n" + "=" * 60)
print("NIKHIL SERVICES TEST COMPLETED")
print("=" * 60)
