# System Architecture & Technical Specification

## 1. System Overview

MaliciousBot is an enterprise-grade hybrid malicious URL detection and investigation system that pairs a fast, deterministic Random Forest machine learning pipeline (**PARI**) with a comprehensive, evidence-corroborating deep analysis fallback subsystem (**Nikhil**).

```
                                      +------------------------------------+
                                      |          User Submits URL          |
                                      +------------------------------------+
                                                        |
                                                        v
                                      +------------------------------------+
                                      |    PARI Feature Extraction (10)    |
                                      |  (url_len, letters, digits, etc.)  |
                                      +------------------------------------+
                                                        |
                                                        v
                                      +------------------------------------+
                                      |     Random Forest Classifier       |
                                      +------------------------------------+
                                                        |
                                         Confidence >= 0.75?
                                        /                  \
                                     YES                    NO
                                     /                        \
                                    v                          v
                     +----------------------------+   +------------------------------------+
                     |    CONFIDENT DECISION      |   |        UNCERTAIN HANDOFF           |
                     |  Saved directly to MySQL   |   |  Scan marked UNCERTAIN in MySQL    |
                     |  (pari_scan, prediction)   |   |  Handoff payload to Nikhil Fallback|
                     +----------------------------+   +------------------------------------+
                                                                       |
                                                                       v
                                                      +------------------------------------+
                                                      |   Nikhil Deterministic Pipeline    |
                                                      |  1. Webpage Analyzer               |
                                                      |  2. Network Analyzer               |
                                                      |  3. Visual Analyzer                |
                                                      |  4. Threat Intel (ThreatFox, etc.) |
                                                      |  5. Prompt-Injection Detector      |
                                                      |  6. AI Analysis (Gatekeeper/Gemini)|
                                                      +------------------------------------+
                                                                       |
                                                                       v
                                                      +------------------------------------+
                                                      |  Persist Evidence to MongoDB Atlas |
                                                      |  Collection: deep_analysis_cases   |
                                                      |  Includes initial_ml.pari_features |
                                                      +------------------------------------+
                                                                       |
                                                                       v
                                                      +------------------------------------+
                                                      |   Multi-Family Corroboration       |
                                                      |   Final Classification Engine      |
                                                      +------------------------------------+
                                                                       |
                                                                       v
                                                      +------------------------------------+
                                                      | Update SQL & MongoDB with Results  |
                                                      +------------------------------------+
```

---

## 2. PARI Core ML Pipeline

### 2.1 Baseline Dataset & Model Training
- **Dataset**: `static/dataset/Phishing.csv` (balanced baseline containing Benign, Defacement, Phishing, Malware samples).
- **Model**: `RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)`.
- **Classes**:
  - `0`: Benign
  - `1`: Defacement
  - `2`: Phishing
  - `3`: Malware
- **Confidence Threshold**: 0.75 (predictions with maximum class probability $\ge 0.75$ are classified as `CONFIDENT`; $< 0.75$ are routed to `UNCERTAIN` for deep fallback analysis).

### 2.2 Exact 10 PARI Feature Extractors
The source of truth for the 10 features is implemented in `User/views.py` and extracted via `MLPredictionService.extract_pari_features(url)`:

1. `url_len`: Length of URL string after stripping protocol prefixes (`http://`, `https://`) and `www.`.
2. `letters_count`: Number of alphabetic characters (`isalpha()`) in the URL.
3. `digits_count`: Number of numeric digits (`isdigit()`) in the URL.
4. `special_chars_count`: Number of punctuation characters (`string.punctuation`) in the URL.
5. `shortened`: Binary indicator (1/0) matching known URL shortening domains (`bit.ly`, `tinyurl.com`, `t.co`, etc.).
6. `abnormal_url`: Binary indicator (1/0) indicating whether hostname is present and matched in the URL path.
7. `secure_http`: Binary indicator (1 if protocol scheme is `https`, 0 otherwise).
8. `have_ip`: Binary indicator (1 if URL contains an IPv4 or hexadecimal IP address instead of domain).
9. `url_region`: Hash-encoded integer (`hash_encode(get_url_region(pri_domain))`) mapping TLD to 180+ regions or "Global".
10. `root_domain`: Hash-encoded integer (`hash_encode(str(pri_domain))`) representing the primary domain.

All 10 features are numeric integers and are persisted in MongoDB Atlas under `initial_ml.pari_features`.

---

## 3. Fallback Handoff Contract

When a scan is `UNCERTAIN`, `MLPredictionService.create_fallback_handoff()` constructs the following contract for `NikhilService.analyze_uncertain_url()`:

```json
{
  "scan_id": 90,
  "url": "https://suspicious-domain.com/login",
  "initial_predicted_class": "Phishing",
  "initial_confidence": 0.62,
  "scan_status": "UNCERTAIN",
  "risk_score": 0.62,
  "model_name": "RandomForest",
  "fallback_endpoint": "/api/fallback/result/",
  "timestamp": "2026-09-30T14:09:02.527410+00:00",
  "pari_features": {
    "url_len": 35,
    "letters_count": 28,
    "digits_count": 0,
    "special_chars_count": 7,
    "shortened": 0,
    "abnormal_url": 1,
    "secure_http": 1,
    "have_ip": 0,
    "url_region": 32604616,
    "root_domain": 51955043
  }
}
```

---

## 4. Nikhil Deterministic Evidence Collection Pipeline

The fallback orchestrator executes six modular collectors in strict deterministic order with individual error boundaries (a failure in one collector does not abort the scan):

1. **Webpage / DOM Analyzer (`WebpageAnalyzer`)**:
   - Fetches target HTML safely with bounded timeouts (5s).
   - Extracts title, form elements, input types (password, credit card, text).
   - Detects login credential theft forms, external form action targets, hidden iframes, and brand impersonation.

2. **Network / DNS / SSL Analyzer (`NetworkAnalyzer`)**:
   - Resolves IP addresses, reverse DNS, and MX records.
   - Inspects SSL/TLS certificates (issuer, validity window, expiry, self-signed detection).
   - Identifies non-standard ports and dynamic DNS hostnames.

3. **Visual / Screenshot Analyzer (`VisualAnalyzer`)**:
   - Headless Playwright/Chromium engine captures full-page visual evidence.
   - Saves screenshots to `screenshots/scan_<id>_<timestamp>.png`.
   - Computes perceptual image hash (dHash/aHash) for visual clustering.

4. **Threat Intelligence & Trusted Domain Engine (`ThreatIntelService`)**:
   - Multi-source intelligence querying ThreatFox, URLhaus, and AbuseIPDB.
   - Strict `free_only_guard` preventing commercial/paid provider leakage.
   - Trusted domain validation (checks top 10,000 domains to avoid false positives on legitimate sites).
   - Local SQL historical correlation against known malicious domains/IPs.

5. **Prompt-Injection Detector (`PromptInjectionDetector`)**:
   - Scans extracted webpage text for adversarial prompt injection patterns.
   - Flags attempts to manipulate downstream LLMs (e.g., "Ignore previous instructions", system prompt extraction).

6. **AI Analysis Engine (`AIAnalyzer` + `AIGatekeeper` + `AIProviderManager`)**:
   - **Gatekeeper**: Evaluates whether LLM analysis is required. If deterministic evidence is conclusive, AI is skipped.
   - **Privacy & Safety**: `EvidenceNormalizer.build_ai_input()` strips all credentials, cookies, and tokens.
   - **Provider Chain**: Primary Google Gemini with automatic failover to OpenRouter / local fallback.
   - **Advisory Role**: AI provides an assessment and reasoning summary; AI is **never** the final authority.

---

## 5. Multi-Family Corroboration & Final Classification

The `FinalClassifier` synthesizes independent evidence families using weighted rules:
- **Evidence Families**: URL Lexical, Webpage DOM, Network/TLS, Threat Intelligence, Visual Similarity, AI Advisory.
- **Corroboration Threshold**: A high-confidence verdict requires corroboration across at least two independent families.
- **Unknown / Needs Review**: If evidence is conflicting, incomplete, or below threshold, the final classification defaults to `Unknown` with status `NEEDS_REVIEW` for manual human analyst inspection.

---

## 6. Project Layout

```
diploma-project/
├── MaliciousBot/              # Django project core configuration
│   ├── settings.py            # Dual-database routing & app settings
│   ├── urls.py                # Global URL router
│   ├── wsgi.py / asgi.py      # WSGI/ASGI entrypoints
│   └── __init__.py
├── User/                      # Main application
│   ├── models.py              # Normalized MySQL relational models
│   ├── views.py               # Request handlers & PARI feature extraction
│   ├── api.py                 # REST APIs for fallback handoff & investigation
│   ├── db_router.py           # Multi-tenant user database router
│   ├── services/
│   │   ├── ml_service.py      # PARI MLPredictionService & confidence routing
│   │   ├── fallback_service.py# Fallback result validation & SQL processing
│   │   └── nikhil/            # Nikhil deep analysis subsystem
│   │       ├── orchestration_service.py  # FallbackOrchestrator
│   │       ├── nikhil_service.py         # Facade service for views/API
│   │       ├── mongodb_repository.py     # MongoDB Atlas persistence
│   │       ├── final_classifier.py       # Multi-family corroboration
│   │       ├── evidence_normalizer.py    # Safe evidence payload builder
│   │       ├── threat_intel.py           # Multi-source threat intel
│   │       └── ...                       # Collectors & AI providers
├── templates/                 # UI HTML templates
├── static/                    # Source CSS, JS, images, baseline dataset
│   └── dataset/Phishing.csv   # Source baseline dataset
├── screenshots/               # Runtime scan screenshot storage (.gitkeep)
├── docs/                      # Consolidated technical documentation
│   ├── ARCHITECTURE.md        # This specification
│   ├── DATABASE.md            # MySQL & MongoDB Atlas database architecture
│   ├── NIKHIL.md              # Nikhil fallback subsystem & threat intel
│   └── VERIFICATION.md        # Comprehensive test & verification reports
├── manage.py                  # Django management script
├── requirements.txt           # Python package dependencies
├── render.yaml                # Render cloud deployment specification
├── start.bat                  # Local development launcher
├── .gitignore                 # Version control exclusions
└── .env                       # Local environment variables
```
