# System Architecture & Technical Specification

## 1. System Overview

MaliciousBot is an enterprise-grade hybrid malicious URL detection and investigation system that pairs a fast, deterministic Random Forest machine learning pipeline (**PARI**) with a comprehensive, evidence-corroborating deep analysis fallback subsystem (**Nikhil**).

```text
                                  USER URL
                                     │
                                     ▼
                            PARI / RANDOM FOREST
                                     │
                           Confidence >= 0.75?
                          /                  \
                        YES                   NO
                        /                       \
                       ▼                         ▼
             CONFIDENT ML PATH           UNCERTAIN HANDOFF
             pari_prediction             pari_prediction
             pari_scan_features          pari_scan_features
             pari_final_decision                 │
                                                 ▼
                                        MYSQL HISTORICAL
                                      INTELLIGENCE CONTEXT
                                                 │
                                                 ▼
                                              NIKHIL
                                                 │
                    ┌────────────────────────────┼────────────────────────────┐
                    ▼                            ▼                            ▼
                 WEBPAGE                      NETWORK                       VISUAL
                    │                            │                            │
                    ├────────────────────────────┼────────────────────────────┤
                    ▼                            ▼                            ▼
               THREAT INTEL               PROMPT INJECTION                 TRUSTED
                    │
                    └────────────────────────────┬────────────────────────────┘
                                                 │
                                                 ▼
                                              MONGODB
                                         Full Detailed Case
                                                 │
                                                 ▼
                                           AI GATEKEEPER
                                                 │
                                                 ▼
                                          GEMINI / FREE AI
                                                 │
                                                 ▼
                                            AI EVIDENCE
                                                 │
                                                 ▼
                                       EVIDENCE CORROBORATION
                                                 │
                                                 ▼
                                           FINAL DECISION
                                            /          \
                                           ▼            ▼
                                         MYSQL       MONGODB
                                   Structured Record  Full Case
```

---

## 2. PARI Core Machine Learning Pipeline

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
The 10 feature extractors are implemented in `MLPredictionService.extract_pari_features(url)` and persisted to MySQL table `pari_scan_features`:
1. `url_len`: Length of URL string after stripping protocol prefixes and `www.`.
2. `letters_count`: Number of alphabetic characters (`isalpha()`) in the URL.
3. `digits_count`: Number of numeric digits (`isdigit()`) in the URL.
4. `special_chars_count`: Number of punctuation characters (`string.punctuation`) in the URL.
5. `shortened`: Binary indicator (1/0) matching known URL shortening domains (`bit.ly`, `tinyurl.com`, `t.co`, etc.).
6. `abnormal_url`: Binary indicator (1/0) indicating whether hostname is present and matched in the URL path.
7. `secure_http`: Binary indicator (1 if protocol scheme is `https`, 0 otherwise).
8. `have_ip`: Binary indicator (1 if URL contains an IPv4 or hexadecimal IP address instead of domain).
9. `url_region`: Hash-encoded integer (`hash_encode(get_url_region(pri_domain))`) mapping TLD to 180+ regions or "Global".
10. `root_domain`: Hash-encoded integer (`hash_encode(str(pri_domain))`) representing the primary domain.

---

## 3. Historical Intelligence & Context Feeding

Before deep analysis begins, `HistoricalIntelligenceService` queries MySQL historical data to provide Nikhil with bounded historical context:
1. **Exact URL History**: Prior occurrences, first seen, last seen, classification history.
2. **Domain Profile**: Prior scan counts, distinct URLs on domain, mixed history status, repeated threat indicators.
3. **Exclusion of Active Scan**: Strict `exclude_scan_id` ensuring a scan never evaluates against itself.
4. **Non-Destructive Visibility**: Respects user's `history_clear_events` boundary for UI while preserving ground truth.
5. **No Direct Malicious Verdicts from History**: Historical evidence acts strictly as supporting context; mixed history generates `mixed historical evidence`, not an automatic threat verdict.

---

## 4. Nikhil Deterministic Fallback & Collectors

1. **Webpage / DOM Analyzer (`WebpageAnalyzer`)**: Fetches HTML safely, detects credential theft forms, external form targets, hidden iframes, and fake login overlays.
2. **Network / DNS / SSL Analyzer (`NetworkAnalyzer`)**: Resolves IP addresses, reverse DNS, and inspects SSL/TLS certificates.
3. **Visual / Screenshot Analyzer (`VisualAnalyzer`)**: Headless Playwright/Chromium engine captures visual proof and computes perceptual image hashes.
4. **Threat Intelligence Engine (`ThreatIntelService`)**: Queries ThreatFox, URLhaus, AbuseIPDB with strict `free_only_guard` preventing commercial/paid API access.
5. **Prompt-Injection Detector (`PromptInjectionDetector`)**: Neutralizes adversarial prompt injections targeting LLMs.
6. **AI Analysis Engine (`AIAnalyzer` + `AIGatekeeper` + `EvidenceNormalizer`)**:
   - Evaluates if AI analysis is genuinely required.
   - Normalizes evidence (stripping credentials, cookies, tokens).
   - Calls Google Gemini 2.5 Flash Free (or OpenRouter backup) strictly as an advisory source.
   - AI is **never** the final authority.

---

## 5. Corroboration Engine (`FinalClassifier`) & Storage Separation

The `FinalClassifier` corroborates multi-family evidence deterministically:
1. **Initial RF Prediction** is permanently stored in `pari_prediction`.
2. **Fallback Analysis** is stored in `pari_scan_fallback`.
3. **Family Evidence Summaries** are stored in `pari_evidence_summary`.
4. **AI Advisory Evidence** is stored in `pari_ai_evidence`.
5. **Authoritative Final Decision** is stored in `pari_final_decision`.
6. **Full Investigation Case** is persisted to MongoDB Atlas collection `deep_analysis_cases`.

---

## 6. DBMS Intelligence & Reporting Layer (`DBMSReportingService`)

The DBMS Intelligence reporting layer in `User/services/dbms_reporting_service.py` provides 15 high-performance, read-only SQL queries with zero N+1 queries and full parameterization:
1. Initial ML uncertainty (`confidence < 0.75`)
2. Initial vs final decision disagreement
3. Fallback usage analysis
4. AI module usage tracking
5. AI vs final decision disagreement
6. Evidence family counts per scan
7. Threat indicator frequency
8. Threat indicator co-occurrence
9. Domain intelligence profile
10. Mixed-history domains
11. Suspicious PARI feature combinations
12. SQL_HISTORY collector usage
13. Evidence provenance reporting
14. Final risk distribution
15. Full scan investigation summary
