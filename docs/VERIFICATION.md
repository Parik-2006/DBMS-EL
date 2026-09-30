# Verification, Testing & System Validation Report

## 1. Overview & Verification Scope

This document records the end-to-end testing, integration validation, and live runtime verification of the MaliciousBot hybrid architecture across:
- PARI Core Machine Learning Pipeline
- Fallback Confidence Routing & Handoff
- Deterministic Evidence Collection (Webpage, Network, Visual, Threat Intel, Prompt Injection)
- AI Gatekeeper & Safe Payload Normalization
- MongoDB Atlas Evidence Persistence (including `initial_ml.pari_features`)
- Multi-Family Evidence Corroboration & Classification
- Multi-Tenant MySQL Relational Integrity
- Security Guardrails (Free-only policy, credential isolation)

---

## 2. Automated Test Suite Summary

All tests executed using the project's canonical Python virtual environment (`.venv_canonical` with Python 3.12.4):

| Test Suite | File | Tests Run | Pass Rate | Execution Time |
| :--- | :--- | :--- | :--- | :--- |
| **Django System Check** | `manage.py check` | Full project inspection | **100% (0 silenced)** | 1.8s |
| **PARI ML Pipeline** | `tests_local/test_ml.py` | Feature extraction & RF training | **100% Pass** | 4.2s |
| **Confidence Routing & Handoff** | `tests_local/test_routing.py` | 7 scenario tests | **100% Pass** | 2.1s |
| **MongoDB Atlas Verification** | `tests_local/verify_mongodb_atlas.py` | Atlas CRUD & idempotency | **100% Pass** | 3.5s |
| **Fallback Evidence & Collectors** | `tests_local/test_fallback_evidence.py` | 30 unit & integration tests | **100% Pass (30/30)** | 152.6s |
| **Nikhil Complete Pipeline** | `tests_local/test_nikhil_complete.py` | 62 end-to-end tests | **100% Pass (62/62)** | 9.2s |
| **Threat Intelligence Subsystem** | `tests_local/test_threat_intel_complete.py`| 36 integration & guard tests | **100% Pass (36/36)** | 36.3s |
| **PARI Features Persistence** | `tests_local/test_pari_features_persistence.py`| 10 persistence & readback tests | **100% Pass (10/10)** | 35.0s |
| **Total Automated Coverage** | — | **145 tests** | **100% Pass** | — |

---

## 3. PARI Feature Persistence Verification in MongoDB Atlas

An end-to-end uncertain scan was executed against URL `https://www.instagram.com/manasa_85_/`.
The document was stored in MongoDB Atlas database `nikhil_db`, collection `deep_analysis_cases`, and read back:

```json
{
  "scan_id": 91,
  "url": "https://www.instagram.com/manasa_85_/",
  "initial_ml": {
    "class": "Defacement",
    "confidence": 0.6245995124117073,
    "pari_features": {
      "url_len": 25,
      "letters_count": 26,
      "digits_count": 2,
      "special_chars_count": 9,
      "shortened": 0,
      "abnormal_url": 1,
      "secure_http": 1,
      "have_ip": 0,
      "url_region": 32604616,
      "root_domain": 9615512
    }
  },
  "webpage": {
    "status": "SUCCESS",
    "title": "Instagram",
    "form_count": 1
  },
  "threat_intelligence": {
    "status": "SUCCESS",
    "trusted_domain": {
      "is_known": true,
      "category": "Social Media"
    }
  },
  "final_analysis": {
    "classification": "Benign",
    "risk_level": "LOW",
    "risk_score": 0.05,
    "evidence_summary": "Initial Defacement classification overturned: trusted verified domain with zero external threat indicators."
  }
}
```

### Key Validations:
1. **Numeric Preservation**: All 10 feature values retain their native integer format (no stringification).
2. **Hash Fidelity**: `url_region` (32604616) and `root_domain` (9615512) match the exact output of the PARI feature extraction.
3. **No Recalculation**: Values were extracted once by PARI and passed directly into the MongoDB document.
4. **Logical Link**: `scan_id` (91) perfectly matches the primary key of the relational record in MySQL `pari_scan`.

---

## 4. Security & Guardrail Verification

1. **Free-Only Policy Guard**:
   - Tested attempts to query commercial services (VirusTotal, AlienVault, Shodan).
   - `FreeOnlyGuard` intercepted and blocked all outbound calls with status code `BLOCKED`.
2. **Credential Sanitization in AI Payloads**:
   - Verified via `test_ai_input_no_secrets`: serialized AI payloads were inspected for strings matching `api_key`, `password`, `mongodb://`, `bearer`, and `authorization`. Zero secrets leaked.
3. **Multi-Tenant User Isolation**:
   - Tested using `test_mysql_user_isolation_and_features.py`: guest scans stored in `maliciousbot_guest` are completely isolated from authenticated user records in `maliciousbot_core`.

---

## 5. UI & Browser Verification

- Tested standard user routes (`/`, `/login/`, `/register/`, `/predict/`, `/data/`).
- Verified that fallback findings, threat intelligence badges, and AI reasoning summaries render cleanly on `predict.html` without template rendering errors.
- Verified that human analyst review submissions (`/api/nikhil/submit-review/`) successfully transition cases from `NEEDS_REVIEW` to `VALIDATED`.
