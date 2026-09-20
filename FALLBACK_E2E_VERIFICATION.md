# Fallback Architecture End-to-End Verification Report

## Overview
This document records the exact runtime execution results of the end-to-end tests performed on the live application (`http://127.0.0.1:8000/`) on branch `nikhil`.

---

## Test Environment
- **Branch**: `nikhil`
- **Application URL**: `http://127.0.0.1:8000/`
- **Authenticated User**: `e2e_user`
- **Confidence Threshold**: `0.75` (75.00%)
- **Test Date/Time**: 2026-09-20T18:55:00+05:30

---

## TEST A — CONFIDENT FLOW (Initial ML Confidence >= 0.75)

### Target URL
`mp3raid.com/music/krizz_kaliko.html`

### Execution Path
```
User submits URL in Browser
  ↓
PARI ML Feature Extraction (10 features)
  ↓
RandomForest Classifier Pipeline
  ↓
Prediction: Benign, Confidence: 86.17% (>= 75.00%)
  ↓
Routing Decision: CONFIDENT
  ↓
Direct SQL Save (pari_scan.status = 'CONFIDENT', pari_prediction.predicted_class = 'Benign')
  ↓
Nikhil Fallback: NOT RUN (Bypassed as intended)
  ↓
Rendered to Browser Result Card
```

### Exact Values Recorded
| Parameter | Recorded Value |
|---|---|
| **Target URL** | `mp3raid.com/music/krizz_kaliko.html` |
| **Initial ML Prediction** | `Benign` |
| **Initial Confidence** | `86.17%` |
| **Routing Status** | `CONFIDENT` |
| **Fallback Invoked** | `No` |
| **Final Classification** | `Benign` |
| **Screenshot Artifact** | `test_a_confident_result_1789910625712.png` |

---

## TEST B — UNCERTAIN FLOW (Initial ML Confidence < 0.75)

### Target URL
`https://suspicious-bank-login-update-account.ru/verify?id=9992`

### Execution Path
```
User submits URL in Browser
  ↓
PARI ML Feature Extraction
  ↓
RandomForest Classifier Pipeline
  ↓
Initial Prediction: Defacement, Initial Confidence: 42.69% (< 75.00%)
  ↓
Routing Decision: UNCERTAIN
  ↓
Nikhil Fallback Invoked
  ├── Webpage Analyzer (Safe DOM fetch with 3s/5s timeouts) → FAILED (Simulated host unreachable)
  ├── Network Analyzer (IP, DNS, SSL cert inspection) → SUCCESS (Extracted host, checked SSL)
  ├── Visual Analyzer (Playwright sandbox or UNAVAILABLE) → UNAVAILABLE (Playwright offline)
  ├── Threat Intelligence (Provider-independent + SQL correlation) → UNAVAILABLE (No API key)
  ├── Prompt Injection Detector (Rule-based pattern matching) → NOT DETECTED
  └── AI Analyzer (Locked stub) → MOCK / NOT AVAILABLE
  ↓
MongoDB Case Record (deep_analysis_cases)
  ↓
Multi-Family Evidence Corroboration Engine
  • Contributing Families: NETWORK (1 family)
  • Top Candidate: Phishing (score 1.5, only 1 family)
  • Evaluation Rule: Insufficient corroboration (requires >= 2 independent families)
  • Final Classification: Unknown / Needs Review (Score: 0.50, Risk: MEDIUM)
  • CRITICAL: Did NOT blindly inherit Initial ML Prediction ('Defacement')
  ↓
PARI Fallback Contract (/api/fallback/result/)
  ↓
SQL Updates (pari_scan.status = 'COMPLETED', pari_scan.fallback_model = 'DeepAnalysis')
  ↓
Rendered to Browser 4-Stage Result Page
```

### Exact Values Recorded
| Parameter | Recorded Value |
|---|---|
| **Scan ID** | `46` |
| **Target URL** | `https://suspicious-bank-login-update-account.ru/verify?id=9992` |
| **Initial ML Prediction** | `Defacement` |
| **Initial Confidence** | `42.69%` |
| **Routing Status** | `UNCERTAIN (< 75%)` |
| **Deep Analysis Status** | `COMPLETED` |
| **Webpage Analysis Status** | `FAILED` |
| **Network Analysis Status** | `SUCCESS` |
| **Visual Analysis Status** | `UNAVAILABLE` |
| **Threat Intelligence Status** | `UNAVAILABLE` |
| **Prompt Injection Status** | `NOT DETECTED` |
| **AI Analysis Status** | `MOCK / NOT AVAILABLE` |
| **Evidence Corroboration** | `1 INDEPENDENT FAMILIES (WEAK)` |
| **Evidence Families Used** | `NETWORK` |
| **Evidence Summary** | `Unknown / Needs Review: Insufficient corroboration for initial indication of Phishing (only 1 family, score 1.5).` |
| **Observed Threat Indicators** | `NETWORK:SSL_VERIFICATION_FAILED` |
| **MongoDB Case Reference** | `local-cache-scan-46` |
| **Final Classification** | `Unknown` |
| **Risk Level** | `MEDIUM` |
| **Risk Score** | `0.50` |
| **SQL Scan Status** | `COMPLETED` |
| **SQL Fallback Model** | `DeepAnalysis` |
| **SQL Predicted Class** | `Unknown` |
| **Separated from Initial ML** | **YES** (Initial: Defacement, Final: Unknown) |
| **Screenshot Artifact** | `test_b_uncertain_result_1789910769551.png` |
| **Session Video Recording** | `e2e_fallback_test_1789910463009.webp` |

---

## Verification Conclusion
Both test flows performed exactly according to the architectural specifications:
1. High-confidence URLs (>= 0.75) are completed immediately by ML without triggering fallback.
2. Low-confidence URLs (< 0.75) trigger Nikhil deep analysis, evaluate multiple evidence families, avoid copying the initial prediction when uncorroborated, record findings in MongoDB and SQL, and clearly present the full breakdown in the browser UI.
