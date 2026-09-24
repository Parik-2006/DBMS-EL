"""
Live API Smoke Test & NPTEL URL Validation Script for Nikhil Fallback.
Executes live queries against ThreatFox, URLhaus, and AbuseIPDB,
then runs full pipeline on the official NPTEL URL.
NEVER prints or exposes API keys or secrets.
"""
import os
import sys
import json
import time

# Django setup
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'MaliciousBot.settings')
import django
django.setup()

from User.services.nikhil.threatfox_provider import ThreatFoxProvider
from User.services.nikhil.urlhaus_provider import URLhausProvider
from User.services.nikhil.abuseipdb_provider import AbuseIPDBProvider
from User.services.nikhil.threat_intel import ThreatIntelService
from User.services.nikhil.orchestration_service import FallbackOrchestrator
from User.services.nikhil.final_classifier import FinalClassifier
from User.services.nikhil.mongodb_repository import MongoDBRepository
from User.models import Scan, URL, Prediction

print("=" * 60)
print("PART 1 — LIVE API SMOKE TESTS (Real Keys from .env)")
print("=" * 60)

# 1. ThreatFox
tf = ThreatFoxProvider()
print("ThreatFox Enabled:", tf.is_enabled())
tf_live_res = tf.lookup_ioc("onlinecourses.nptel.ac.in")
print(f"ThreatFox Status: {tf_live_res.get('status')}")
print(f"ThreatFox Hits: {tf_live_res.get('hits')}")
print(f"ThreatFox Message: {tf_live_res.get('message')}")

# 2. URLhaus
uh = URLhausProvider()
print("\nURLhaus Enabled:", uh.is_enabled())
uh_live_res = uh.lookup_url("https://onlinecourses.nptel.ac.in")
print(f"URLhaus Status: {uh_live_res.get('status')}")
print(f"URLhaus Hits: {uh_live_res.get('hits')}")
print(f"URLhaus Message: {uh_live_res.get('message')}")

# 3. AbuseIPDB
aip = AbuseIPDBProvider()
print("\nAbuseIPDB Enabled:", aip.is_enabled())
# Query standard public DNS IP (8.8.8.8) for clean live test
aip_live_res = aip.check_ip("8.8.8.8")
print(f"AbuseIPDB Status: {aip_live_res.get('status')}")
print(f"AbuseIPDB IP: {aip_live_res.get('ip')}")
print(f"AbuseIPDB Score: {aip_live_res.get('abuse_confidence_score')}%")
print(f"AbuseIPDB Reports: {aip_live_res.get('total_reports')}")
print(f"AbuseIPDB Message: {aip_live_res.get('message')}")

print("\n" + "=" * 60)
print("PART 2 — LIVE NPTEL URL DEEP ANALYSIS EXECUTION")
print("=" * 60)

nptel_url = "https://onlinecourses.nptel.ac.in/e-learning/course/noc26_hs247?unitId=38&lessonId=39"
print(f"Target URL: {nptel_url}")

# Create or reuse a Scan record in SQL for realistic integration
url_obj, _ = URL.objects.get_or_create(url=nptel_url)
scan_obj = Scan.objects.create(
    url=url_obj,
    status='UNCERTAIN'
)
scan_id = scan_obj.id
print(f"Scan ID: {scan_id}")

initial_prediction = "Benign"
initial_confidence = 0.68  # Uncertain (< 0.75 threshold)

print(f"Initial ML Class: {initial_prediction} (Confidence: {initial_confidence:.2f})")

# Execute Orchestration
orchestrator = FallbackOrchestrator()
evidence_data, mongo_doc_id = orchestrator.perform_deep_analysis(
    scan_id=scan_id,
    url=nptel_url,
    initial_prediction=initial_prediction,
    initial_confidence=initial_confidence
)

# Extract Threat Intelligence Evidence
ti_data = evidence_data.get("threat_intelligence", {})
print("\n--- THREAT INTELLIGENCE RESULTS ---")
print(f"Overall TI Status: {ti_data.get('status')}")
print(f"TI Reputation: {ti_data.get('reputation')}")
sources = ti_data.get("sources", {})
print(f"ThreatFox: {sources.get('threatfox', {}).get('status')} (hits: {sources.get('threatfox', {}).get('hits', 0)})")
print(f"URLhaus: {sources.get('urlhaus', {}).get('status')} (hits: {sources.get('urlhaus', {}).get('hits', 0)})")
print(f"AbuseIPDB: {sources.get('abuseipdb', {}).get('status')} (score: {sources.get('abuseipdb', {}).get('abuse_confidence_score', 0)}%)")
print(f"Local SQL Correlation: {sources.get('local_sql', {}).get('status')} (known malicious: {sources.get('local_sql', {}).get('known_malicious_in_domain', 0)})")
print(f"Trusted Domain: category='{sources.get('trusted_domain', {}).get('category')}', known={sources.get('trusted_domain', {}).get('is_known')}")
print(f"UI Summary: {ti_data.get('summary', {}).get('threat_intel_ui_summary')}")

# AI Analysis
ai_data = evidence_data.get("ai_analysis", {})
print("\n--- AI ANALYSIS ---")
print(f"AI Status: {ai_data.get('status')}")
print(f"AI Required (Gatekeeper): {ai_data.get('ai_required')}")
print(f"AI Provider: {ai_data.get('provider')}")
print(f"AI Assessment: {ai_data.get('assessment')}")

# Final Corroboration & Classification
classifier = FinalClassifier()
final_result = classifier.classify(initial_prediction, initial_confidence, evidence_data)

print("\n--- CORROBORATION & FINAL CLASSIFICATION ---")
print(f"Final Classification: {final_result.get('final_classification')}")
print(f"Risk Level: {final_result.get('risk_level')}")
print(f"Risk Score: {final_result.get('risk_score')}")
corrob = final_result.get("corroboration", {})
print(f"Corroboration Strength: {corrob.get('strength')}")
print(f"Independent Families Used: {corrob.get('independent_families')} ({', '.join(corrob.get('families_used', []))})")
print(f"Evidence Summary: {final_result.get('evidence_summary')}")

# MongoDB Verification
mongo_repo = MongoDBRepository()
stored_doc = mongo_repo.get_evidence(scan_id)
print("\n--- MONGODB ATLAS VERIFICATION ---")
if stored_doc:
    print(f"MongoDB Document Found: YES (ID: {stored_doc.get('_id')})")
    ti_stored = stored_doc.get("threat_intelligence", {})
    print(f"TI in MongoDB: {bool(ti_stored)}")
    print(f"TI Status in MongoDB: {ti_stored.get('status')}")
else:
    print("MongoDB Document Found: NO (Stored in fallback cache)")

# Check SQL storage
from User.services.fallback_service import FallbackIntegrationService
fallback_payload = {
    'scan_id': scan_id,
    'analysis_status': 'COMPLETED',
    'final_classification': final_result['final_classification'],
    'risk_level': final_result['risk_level'],
    'risk_score': final_result['risk_score'],
    'evidence_summary': final_result['evidence_summary'],
    'threat_indicators': final_result.get('threat_indicators', []),
    'mongo_document_reference': mongo_doc_id
}
sql_save_res = FallbackIntegrationService.process_fallback_result(fallback_payload)
print("\n--- SQL DATABASE PERSISTENCE ---")
print(f"SQL Save Success: {sql_save_res.get('success')}")
print(f"SQL Message: {sql_save_res.get('message')}")

print("\n" + "=" * 60)
print("LIVE VALIDATION COMPLETE")
print("=" * 60)
