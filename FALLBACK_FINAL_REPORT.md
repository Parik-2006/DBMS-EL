# Fallback Architecture Final Report

## Executive Summary
This report documents the completed implementation of the evidence-driven fallback architecture on branch `nikhil` of the repository `https://github.com/Parik-2006/DBMS-EL.git` located at `P:\DBMS EL\diploma-project`.

Per explicit directives:
- **REAL LLM / GEMINI IS EXCLUDED FROM THIS PHASE**: The AI analyzer is locked as `MOCK / UNAVAILABLE`. No external LLM APIs were called or installed. The system is strictly evidence-driven through deterministic analyzers and rules.
- **EXISTING ML & SQL BASELINE PRESERVED**: The 400-row baseline dataset, RandomForest classifier, LogisticRegression, feature extraction, 0.75 confidence threshold, PARI SQL schema, correlation services, and user authentication were preserved without alteration.

---

## 1. System Architecture

```
                                  [ Incoming URL ]
                                         │
                                         ▼
                           [ Initial ML Model (RandomForest) ]
                           [ Feature Extraction: 10 Features ]
                                         │
                  ┌──────────────────────┴──────────────────────┐
                  ▼                                             ▼
        [ Confidence >= 0.75 ]                        [ Confidence < 0.75 ]
                  │                                             │
                  ▼                                             ▼
          [ CONFIDENT PATH ]                           [ UNCERTAIN PATH ]
          • Direct SQL Save                            • Invoke Nikhil Fallback
          • Status: CONFIDENT                          • Status: UNCERTAIN
          • Rendered to UI                             • 6 Deep Analysis Collectors
                                                                │
           ┌────────────────────────────────────────────────────┴───────────────────────────────────────┐
           ▼                                                                                            ▼
   [ Evidence Collection ]                                                                   [ Case Storage ]
   1. Webpage Analyzer (DOM, forms, password inputs, cross-domain targets, indicators)       • MongoDB Atlas (deep_analysis_cases)
   2. Network Analyzer (IP, reverse DNS, SSL cert validity, redirect chain)                  • Linked by scan_id
   3. Visual Analyzer (Playwright sandbox or truthful UNAVAILABLE)                           • Resilient in-memory fallback cache
   4. Threat Intel (Provider-independent + local SQL correlation)                                       │
   5. Prompt Injection Detector (Deterministic rules, NO LLM)                                           │
   6. AI Analyzer (Strictly MOCK / UNAVAILABLE)                                                         ▼
           │                                                                                 [ Multi-Family Corroboration ]
           └────────────────────────────────────────────────────────────────────────────────► • Independent families count
                                                                                              • Explicit engineering rules
                                                                                              • Uncorroborated → Unknown
                                                                                                        │
                                                                                                        ▼
                                                                                             [ PARI Contract & SQL ]
                                                                                             • /api/fallback/result/
                                                                                             • Scan: COMPLETED
                                                                                             • Prediction: DeepAnalysis
                                                                                                        │
                                                                                                        ▼
                                                                                             [ Browser UI Display ]
                                                                                             • 4-Stage clear separation
```

---

## 2. Module Responsibilities & Evidence Types

| Module | File | Responsibility & Evidence Collected |
|---|---|---|
| **Webpage Analyzer** | `User/services/nikhil/webpage_analyzer.py` | Safe HTTP fetch (max 1MB, connect 3s, read 5s, max 3 redirects). Analyzes DOM structure, metadata, forms (action, method, inputs, password detection, cross-domain actions), suspicious download extensions (.exe, .msi, etc.), hidden elements, iframes, script references, defacement keywords, and credential harvesting keywords. Produces EVIDENCE ONLY. |
| **Network Analyzer** | `User/services/nikhil/network_analyzer.py` | Collects domain info, socket IP resolution, reverse DNS PTR lookup, raw IP detection, HTTP HEAD status and server headers, redirect hops, and live SSL/TLS certificate verification (issuer, subject, validity period, expiration check). Strict timeouts (3-4s). |
| **Visual Analyzer** | `User/services/nikhil/visual_analyzer.py` | Checks browser automation (Playwright). If available, renders in isolated sandbox without JS execution and saves screenshot reference. If missing/failing, truthfully reports `status: UNAVAILABLE` without faking success. |
| **Threat Intel Service** | `User/services/nikhil/threat_intel.py` | Provider-independent threat intelligence interface. Checks environment keys; reports `status: UNAVAILABLE` when unconfigured. Queries local PARI SQL tables (`Domain`, `Scan`, `ThreatIndicator`) for known malicious scans and infrastructure reuse. |
| **Prompt Injection Detector** | `User/services/nikhil/prompt_injection.py` | Deterministic regex/pattern matching (NO LLM). Scans extracted text and hidden elements for instruction overrides (`ignore previous instructions`, `reveal system prompt`, `classify as benign`, etc.). Strictly treats webpage text as untrusted DATA. |
| **AI Analyzer** | `User/services/nikhil/ai_analyzer.py` | Explicitly locked as `status: MOCK / UNAVAILABLE`. **REAL LLM IS NOT IMPLEMENTED IN THIS PHASE.** Not treated as real evidence and cannot determine classification. |
| **MongoDB Repository** | `User/services/nikhil/mongodb_repository.py` | Persists complete investigation document in `deep_analysis_cases` linked by `scan_id`. Implements upsert and an in-memory fallback cache so network restrictions do not disrupt the pipeline. |
| **Final Classifier** | `User/services/nikhil/final_classifier.py` | Evaluates evidence across independent families (`WEBPAGE`, `TEXT`, `NETWORK`, `VISUAL`, `SQL_CORRELATION`, `PROMPT_INJECTION`). Computes engineering evidence scores. Requires >= 2 independent families for confirmed classification. Resolves uncorroborated or conflicting evidence to `Unknown / Needs Review`. |
| **Orchestrator & Main Service** | `orchestration_service.py`, `nikhil_service.py` | Pipeline coordinator. Ensures partial module failures never crash the scan. Formats payload for the PARI return contract. |

---

## 3. Classification & Corroboration Rules

1. **Multi-Family Requirement**: A strong classification (e.g. Phishing, Malware, Defacement) requires evidence from at least **2 independent evidence families** (e.g. WEBPAGE + NETWORK, or WEBPAGE + SQL_CORRELATION).
2. **Insufficient Evidence Fallback**: If an uncertain URL generates only a single weak indicator (e.g. only 1 family, score < 3.5) or no meaningful evidence, the engine classifies it as **`Unknown`** (`Unknown / Needs Review`) with `risk_level: MEDIUM` and `risk_score: 0.50`.
3. **No Automatic Inheritance**: The final classifier **NEVER** blindly inherits the initial Random Forest class when evidence is insufficient.
4. **Conflicting Signals**: If independent signals contradict each other (e.g. Phishing signals vs verified Benign signals with close scores), the engine flags the case as `Unknown / Needs Review` for analyst intervention.

---

## 4. Real vs Mock Components Matrix

| Component | Nature | Description |
|---|---|---|
| **Webpage / HTML DOM Analyzer** | **REAL** | Performs live HTTP streaming and BeautifulSoup DOM inspection. |
| **Network / DNS / SSL Analyzer** | **REAL** | Performs live socket DNS queries, IP lookups, and TLS/SSL certificate handshakes. |
| **Prompt-Injection Detector** | **REAL** | Performs deterministic rule-based pattern matching on page text without an LLM. |
| **SQL Correlation Layer** | **REAL** | Live queries on Django SQLite/MySQL database (`Scan`, `Domain`, `ThreatIndicator`). |
| **Evidence Corroboration Engine** | **REAL** | Rule-based multi-family scoring algorithm. |
| **MongoDB Case Storage** | **REAL** | Real `pymongo` driver integration with Atlas connection attempt and local fallback cache. |
| **PARI Integration Contract** | **REAL** | Validates and updates real SQL `Scan` and `Prediction` records. |
| **Visual / Screenshot Analyzer** | **REAL INTERFACE** | Truthfully reports `UNAVAILABLE` when browser automation libraries are not installed. Never fakes screenshots. |
| **Threat Intelligence Interface** | **REAL INTERFACE** | Truthfully reports `UNAVAILABLE` when external API keys are omitted; queries real local SQL. |
| **AI / Multimodal LLM Analyzer** | **MOCK / UNAVAILABLE** | **Strictly MOCK stub. Real LLM / Gemini is NOT implemented in this phase.** |

---

## 5. Test & Runtime Verification Summary

### Automated Test Suite (`test_fallback_evidence.py`)
- **Total Tests**: 30 comprehensive unit & integration test cases.
- **Result**: `Ran 30 tests in 111.411s — OK (100% Pass)`.
- **System Check**: `python manage.py check` — `0 Errors`.

### End-to-End Live Browser Runs

#### TEST A — CONFIDENT FLOW
- **URL**: `mp3raid.com/music/krizz_kaliko.html`
- **Initial ML Confidence**: `86.17%` (>= 75.00%)
- **Status**: `CONFIDENT`
- **Final Classification**: `Benign`
- **Fallback Invocation**: Skipped directly to result card.

#### TEST B — UNCERTAIN FLOW
- **URL**: `https://suspicious-bank-login-update-account.ru/verify?id=9992`
- **Initial ML Prediction**: `Defacement`
- **Initial Confidence**: `42.69%` (< 75.00% &rarr; UNCERTAIN)
- **Deep Analysis**: `COMPLETED`
- **Collector Statuses**: Webpage: `FAILED` (simulated non-existent host), Network: `SUCCESS`, Visual: `UNAVAILABLE`, Threat Intel: `UNAVAILABLE`, Prompt Injection: `NOT DETECTED`, AI: `MOCK / NOT AVAILABLE`.
- **Evidence Corroboration**: `1 INDEPENDENT FAMILIES (WEAK)`
- **Final Classification**: **`Unknown`** (Needs Review, Risk: MEDIUM, Score: 0.50).
- **Separated from Initial ML**: Confirmed on UI and in database. Initial `Defacement` was NOT inherited.
- **SQL Scan Record**: Scan ID 46 updated to status `COMPLETED`, fallback_model `DeepAnalysis`, prediction `Unknown`.

---

## 6. Known Limitations & Future Roadmap
1. **Real LLM / Gemini Integration**: Excluded from this phase by specification. The `AIAnalyzer` interface is ready for plug-and-play LLM integration in a future milestone.
2. **External Threat Intel APIs**: VirusTotal and AlienVault endpoints require external API keys configured in environment variables (`VIRUSTOTAL_API_KEY`); when unconfigured, the system safely falls back to local SQL correlation.
3. **Headless Browser (Playwright)**: When headless browser dependencies are not installed in the Python environment, visual capture gracefully reports `UNAVAILABLE`.
