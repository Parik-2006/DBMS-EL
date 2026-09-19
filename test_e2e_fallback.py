import os
import django
import json
import time
from django.test import Client
from django.utils import timezone

# Configure Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'MaliciousBot.settings')
django.setup()

from User.models import Scan, URL, Domain, Prediction
from User.services.nikhil.orchestration_service import FallbackOrchestrator
from User.services.nikhil.final_classifier import FinalClassifier

def run_e2e_test():
    print("=" * 60)
    print("END-TO-END FALLBACK INTEGRATION TEST")
    print("=" * 60)

    # 1. Setup Test Data in MySQL
    print("Step 1: Setting up PARI test data...")
    domain, _ = Domain.objects.get_or_create(domain_name="e2e-test.com")
    url_obj, _ = URL.objects.get_or_create(url="https://e2e-test.com/phish", domain=domain)
    
    scan = Scan.objects.create(
        url=url_obj,
        status="UNCERTAIN",
        initial_model="RandomForest"
    )
    
    Prediction.objects.create(
        scan=scan,
        model_name="RandomForest",
        predicted_class="Phishing",
        confidence=0.60,
        risk_score=0.60
    )
    
    print(f"Created UNCERTAIN scan: {scan.id}")

    # 2. Run Nikhil Orchestration
    print("\nStep 2: Running Nikhil Deep Analysis Orchestration...")
    orchestrator = FallbackOrchestrator()
    # This will hit real MongoDB Atlas
    evidence, mongo_id = orchestrator.perform_deep_analysis(scan.id, scan.url.url)
    
    print(f"Deep Analysis Status: {evidence['analysis_status']}")
    print(f"Evidence stored in MongoDB. Document ID: {mongo_id}")
    print(f"Webpage Analysis: {evidence['webpage']['status']}")
    print(f"Network Analysis: {evidence['network']['status']}")
    print(f"AI Analysis: {evidence['ai_analysis']['status']} (MOCK)")

    # 3. Perform Final Classification
    print("\nStep 3: Performing Final Classification...")
    classifier = FinalClassifier()
    final_result = classifier.classify(
        "Phishing", 0.60, evidence
    )
    print(f"Final Classification: {final_result['final_classification']}")
    print(f"Risk Level: {final_result['risk_level']}")

    # 4. Return Result to PARI (via API)
    print("\nStep 4: Returning Result to PARI Integration Endpoint...")
    payload = {
        "scan_id": scan.id,
        "analysis_status": "COMPLETED",
        "final_classification": final_result["final_classification"],
        "risk_level": final_result["risk_level"],
        "risk_score": final_result["risk_score"],
        "evidence_summary": final_result["evidence_summary"],
        "threat_indicators": final_result["threat_indicators"],
        "mongo_document_reference": mongo_id,
        "original_prediction": "Phishing",
        "original_confidence": 0.60
    }
    
    client = Client()
    response = client.post(
        '/api/fallback/result/',
        data=json.dumps(payload),
        content_type='application/json'
    )
    
    print(f"API Response Status: {response.status_code}")
    # Debugging: Print full response for 400
    if response.status_code == 400:
        print(f"API Response JSON: {response.json() if 'application/json' in response['Content-Type'] else 'Not JSON'}")

    # 5. Verify PARI MySQL Update
    print("\nStep 5: Verifying PARI SQL Update...")
    scan.refresh_from_db()
    prediction = scan.prediction
    
    print(f"Final Scan Status: {scan.status}")
    print(f"Final Predicted Class: {prediction.predicted_class}")
    print(f"Final Risk Score: {prediction.risk_score}")
    print(f"Fallback Model: {scan.fallback_model}")
    
    if scan.status == "COMPLETED" and prediction.predicted_class == final_result["final_classification"]:
        print("\nSUCCESS: End-to-End Fallback Integration Verified.")
    else:
        print("\nFAILED: Integration mismatch.")

    # Cleanup (Optional - keep for manual verification if needed, but let's delete test scan)
    # scan.delete() 
    
    print("=" * 60)

if __name__ == "__main__":
    run_e2e_test()
