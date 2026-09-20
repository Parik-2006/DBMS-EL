# Fallback Architecture Current State Audit

## Overview
This document records the exact state of all modules in the Nikhil fallback architecture within `P:\DBMS EL\diploma-project` on branch `nikhil`, following the implementation of the evidence-driven fallback pipeline.

---

## Module Status Matrix

| Module | File Location | Status | Implementation Details |
|---|---|---|---|
| **Fallback Orchestrator** | `User/services/nikhil/orchestration_service.py` | **IMPLEMENTED & VERIFIED** | Coordinates 6 evidence collectors safely in isolated try/except blocks. Computes timing metrics, writes cases to MongoDB Atlas (with in-memory fallback), and ensures partial module failures never crash the scan. |
| **Webpage / HTML Analyzer** | `User/services/nikhil/webpage_analyzer.py` | **IMPLEMENTED & VERIFIED** | Real DOM analysis with streaming, 1MB limit, 3s connect / 5s read timeout, max 3 redirects. Extracts page title, visible text, metadata, forms (method, action, password inputs, cross-domain targets), iframes, script references, download links, and hidden content. Detects indicators: `PASSWORD_FORM`, `CROSS_DOMAIN_FORM`, `SUSPICIOUS_REDIRECT`, `SUSPICIOUS_DOWNLOAD`, `HIDDEN_CONTENT`, `SUSPICIOUS_IFRAME`, `SUSPICIOUS_SCRIPT`, `DEFACEMENT_TEXT`, `CREDENTIAL_HARVESTING_TEXT`. |
| **Visual / Screenshot Analyzer** | `User/services/nikhil/visual_analyzer.py` | **IMPLEMENTED & VERIFIED** | Checks Playwright / headless automation availability. If present, runs in sandbox without JS execution and saves screenshot reference. If browser library is missing or fails, gracefully and truthfully reports `status: UNAVAILABLE` without faking data. |
| **Network / Domain Analyzer** | `User/services/nikhil/network_analyzer.py` | **IMPLEMENTED & VERIFIED** | Performs socket IP resolution (`gethostbyname_ex`), reverse DNS PTR lookups, raw IP detection, HTTP HEAD response metadata (status code, server, redirect chain), and live TLS/SSL certificate verification (trusted CA, issuer, subject, validity dates, expiration check) with strict 3-4s timeouts. |
| **Threat Intelligence Interface** | `User/services/nikhil/threat_intel.py` | **IMPLEMENTED & VERIFIED** | Provider-independent interface. Reads environment API keys (e.g. `VIRUSTOTAL_API_KEY`). Reports `status: UNAVAILABLE` when unconfigured without inventing fake results. Queries local PARI SQL tables (`Domain`, `Scan`, `ThreatIndicator`, `ScanIndicator`) to detect previous malicious scans and infrastructure sharing. |
| **Prompt-Injection Detector** | `User/services/nikhil/prompt_injection.py` | **IMPLEMENTED & VERIFIED** | Deterministic, rule-based pattern matching (NO LLM). Inspects extracted visible text and hidden elements for instruction overrides (`IGNORE_PREVIOUS_INSTRUCTIONS`, `REVEAL_SYSTEM_PROMPT`, `CLASSIFIER_OVERRIDE_DIRECTIVE`, `ALWAYS_RETURN_SAFE_DIRECTIVE`, `DELIMITER_INJECTION_SYSTEM`, shell/tool execution syntax). Strictly treats page content as untrusted DATA. |
| **AI / LLM Analyzer** | `User/services/nikhil/ai_analyzer.py` | **MOCK / UNAVAILABLE** | **REAL LLM / GEMINI IS NOT IMPLEMENTED IN THIS PHASE.** Explicitly returns `status: MOCK / UNAVAILABLE`. Prohibited from acting as authoritative or independently setting the final classification. |
| **MongoDB Case Repository** | `User/services/nikhil/mongodb_repository.py` | **IMPLEMENTED & VERIFIED** | Targets `deep_analysis_cases` collection linked by `scan_id`. Implements upsert on `scan_id`, stores document references instead of raw binaries, and features an in-memory resilient fallback cache so network restrictions do not disrupt scan execution. |
| **Final Classifier & Corroboration Engine** | `User/services/nikhil/final_classifier.py` | **IMPLEMENTED & VERIFIED** | Multi-family evidence corroboration engine. Evaluates evidence across WEBPAGE, TEXT, NETWORK, VISUAL, SQL_CORRELATION, and PROMPT_INJECTION. Applies explicit engineering rules for Benign, Phishing, Malware, and Defacement. Requires >= 2 independent families for confirmed classification. Resolves uncorroborated or conflicting evidence to `Unknown / Needs Review` rather than blindly inheriting initial ML classes. |
| **Main Nikhil Service** | `User/services/nikhil/nikhil_service.py` | **IMPLEMENTED & VERIFIED** | Main coordinator invoked when initial ML confidence < 0.75. Orchestrates deep analysis, calls corroboration engine, updates MongoDB case record, and formats payload matching the PARI return contract. |
| **PARI Integration Service** | `User/services/fallback_service.py` | **VERIFIED** | Validates fallback payload, updates `pari_scan` (status: COMPLETED, fallback_model: DeepAnalysis), updates `pari_prediction` (model_name: DeepAnalysis, predicted_class, risk_score), and links detected threat indicators in `pari_threat_indicator` and `pari_scan_indicator`. |
| **PARI ML Prediction Service** | `User/services/ml_service.py` | **VERIFIED** | RandomForest classifier trained on 400-row baseline dataset. 0.75 confidence threshold enforces CONFIDENT vs UNCERTAIN routing. |
| **Browser Result Page** | `templates/predict.html` | **IMPLEMENTED & VERIFIED** | Updated with clean 4-stage UI. Clearly separates Initial ML Prediction from Final Fallback Classification. Renders module status pills (Webpage, Network, Visual, Threat Intel, Prompt Injection, AI), evidence family count, and threat indicator tags. |

---

## Summary of Verification
- **Automated Test Suite**: 30 unit & integration tests executed (`test_fallback_evidence.py`) — **100% PASS** (OK in 111s).
- **System Check**: `python manage.py check` — **0 Errors**.
- **Live Browser Tests**:
  - Test A (CONFIDENT): `mp3raid.com/music/krizz_kaliko.html` &rarr; 86.17% Benign &rarr; CONFIDENT directly.
  - Test B (UNCERTAIN): `https://suspicious-bank-login-update-account.ru/verify?id=9992` &rarr; Initial 42.69% Defacement &rarr; Fallback Orchestrated &rarr; Final: `Unknown` (Needs Review, Risk: MEDIUM 0.50).
