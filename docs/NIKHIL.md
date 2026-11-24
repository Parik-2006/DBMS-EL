# Nikhil Fallback & Deep Evidence Subsystem

## 1. System Mission & Philosophy

The Nikhil Fallback Subsystem activates when the PARI Random Forest model evaluates a URL with uncertainty (confidence score $< 0.75$).

### Core Tenets:
1. **Deterministic Workflow**: No LLM orchestrates or decides the execution flow. The pipeline is pure deterministic Python code.
2. **Multi-Family Corroboration**: No single indicator is trusted blindly. High confidence requires corroboration across multiple independent families (Lexical, DOM, Network, Visual, Threat Intel, SQL History).
3. **AI as Advisor Only**: Large Language Models (Gemini Free primary / OpenRouter Free backup) act strictly as forensic interpreters of normalized evidence. The AI **never** directly writes the final verdict.
4. **Strict Free-Only Policy**: No paid APIs are accessed (`FREE_ONLY=true`, `ALLOW_PAID_PROVIDERS=false`). Only open, community-driven threat feeds are integrated.
5. **Human-in-the-Loop Safeguard**: If evidence remains conflicting or inconclusive, the system safely defaults to `Unknown` (Needs Review) and registers the case for analyst validation in `pari_analyst_review`.

---

## 2. MySQL Historical Intelligence Integration (`SQL_HISTORY`)

Before collectors run, `HistoricalIntelligenceService` queries MySQL relational tables for historical memory:
- **Exact URL History**: Previous scans, first seen, last seen, historical classification breakdown.
- **Domain Memory**: Scan frequency, distinct URLs on domain, mixed history status (`has_mixed_outcomes`).
- **Threat Indicator Catalog**: Recurring indicators on record across prior scans.
- **Strict Current-Scan Exclusion**: Active `scan_id` is excluded to prevent circular confirmation bias.
- **Semantic Rule**: Historical evidence NEVER directly produces a malicious verdict. Mixed history is surfaced as `mixed historical evidence`, leaving the final determination to current corroboration.

---

## 3. Evidence Collectors

### 3.1 Webpage & DOM Analyzer (`WebpageAnalyzer`)
- **Safe Retrieval**: Fetches HTML using bounded timeouts and safe headers.
- **Form Inspection**: Detects password inputs and external (cross-domain) `action` targets.
- **Phishing Heuristics**: Flags cross-domain form submissions, concealed iframes, hidden content, eval-style scripts, executable download links, credential-harvesting and defacement phrases. (No brand-mismatch detection.)
- **Outbound safety (Phase 1)**: fetches go through `User/security/outbound.py` (public destinations only, DNS-pinned, redirects validated per hop); blocked targets yield status `BLOCKED`.

### 3.2 Network, DNS & SSL Analyzer (`NetworkAnalyzer`)
- **Resolution**: Resolves and validates A/AAAA addresses (public only) and reverse DNS PTR. (No MX records.)
- **SSL/TLS Validation**: Validates the certificate chain against the hostname on the pinned IP, records issuer/subject/validity and expiry. `verified=None` means no handshake was possible (not an invalid certificate). (No certificate-age check.)

### 3.3 Visual Analyzer (`VisualAnalyzer`)
- **Automated Capture**: Uses headless Playwright / Chromium to render the page in a secure sandbox.
- **Storage**: `MEDIA_ROOT/screenshots/<tenant>/<investigation-uuid>.png`, served only to the scan owner (Phase 1).
- **Egress control (Phase 1)**: all browser requests are intercepted and fulfilled by the pinned outbound transport; JS, downloads and service workers are disabled. (No perceptual hashing.)

### 3.4 Threat Intelligence Engine (`ThreatIntelService`)
Integrates three verified free community providers plus local database correlation:
- **ThreatFox (`ThreatFoxProvider`)**: Checks domains, IPs, and URLs against abuse.ch ThreatFox IOC database.
- **URLhaus (`URLhausProvider`)**: Queries active malware distribution URLs and payloads.
- **AbuseIPDB (`AbuseIPDBProvider`)**: Assesses IP abuse confidence scores and historical attack reports.
- **Free-Only Guard (`free_only_guard.py`)**: Intercepts requests and enforces hard blocks against commercial paid services (VirusTotal, AlienVault, Shodan, Recorded Future).
- **Trusted Domain Catalog (`TrustedDomainService`)**: Maintains a curated list of 44 well-known domains plus trusted TLDs as supporting evidence (never an automatic Benign).
- **Local SQL Historical Correlation**: Delegates to `HistoricalIntelligenceService` over MySQL models.

### 3.5 Prompt-Injection Detector (`PromptInjectionDetector`)
- Analyzes extracted webpage text and hidden tags for prompt-injection attacks.
- Identifies jailbreak patterns targeting downstream LLMs.
- Produces a detection signal only; the AI never receives raw page text (only normalized findings), which is the actual injection defence.

### 3.6 AI Gatekeeper & Provider Manager (`AIAnalyzer`)
- **AIGatekeeper**: Evaluates whether AI analysis is necessary. If deterministic indicators are already conclusive or rate limits are approached, AI execution is skipped (`status: NOT_RUN`).
- **EvidenceNormalizer**: Strips raw HTML, cookies, tokens, and authorization headers, packaging a safe, bounded payload.
- **Failover Chain**: Primary Google Gemini Free (`gemini-2.5-flash`) with automated failover to OpenRouter Free.
- **Advisory Role**: Generates risk assessment, observations, and reasoning summary. Persisted to `pari_ai_evidence`.

---

## 4. Corroboration Engine (`FinalClassifier`)

The `FinalClassifier` corroborates multi-source evidence using an engineering score matrix:

| Family | Negative Signals (Benign) | Positive Signals (Threat) |
| :--- | :--- | :--- |
| **URL Lexical** | Low entropy, standard length, recognized TLD | High digit ratio, brand spoofing, hex IP, URL shortener |
| **Webpage DOM** | Standard navigation, valid relative links | External credential action, hidden iframes, password input on unauthenticated page |
| **Network / SSL** | Established certificate (> 90 days), valid CA | Self-signed certificate, expiring < 14 days, dynamic DNS host |
| **Threat Intel** | Zero community reports, trusted domain verified | ThreatFox positive match, URLhaus active malware, AbuseIPDB $> 50\%$ |
| **SQL History** | Clean historical record across multiple prior scans | Repeated threat indicators, historical malicious domain associations |
| **AI Advisory** | Assessment confirms standard benign site | Assessment identifies phishing indicators or deceptive intent |

### Decision Flow:
1. **Threat-intel matches**: ThreatFox (+3.0) and URLhaus (+3.5) matches add weighted Malware/Phishing evidence; a single match can still end as `Unknown` when it conflicts with other evidence (no automatic verdict).
2. **Corroborated Threat**: If two or more independent families show strong positive signals $\rightarrow$ classify as `Phishing` / `Malware` / `Defacement`.
3. **Corroborated Benign**: If trusted domain is verified and all collectors report clean status $\rightarrow$ classify as `Benign` (`LOW` risk).
4. **Conflict / Ambiguity**: If signals contradict or evidence is insufficient $\rightarrow$ classify as `Unknown` (`MEDIUM` risk, status `NEEDS_REVIEW`).

---

## 5. API Endpoints

> Phase 1: browser APIs require login, CSRF for unsafe methods and scan ownership in the caller's own tenant database; `POST /api/fallback/result/` requires `Authorization: Bearer $FALLBACK_SERVICE_TOKEN` plus `tenant_id` and `investigation_id`; `POST /api/nikhil/submit-review/` requires the `User.submit_review` permission (Analyst role). See `docs/PHASE1_IMPLEMENTATION.md`.

- `POST /api/fallback/result/`: Ingests deep analysis results and updates SQL/MongoDB.
- `GET /api/fallback/uncertain-scans/`: Returns queue of uncertain scans awaiting fallback processing.
- `GET /api/fallback/scan-status/<scan_id>/`: Queries real-time status of a scan (`UNCERTAIN`, `DEEP_ANALYSIS`, `COMPLETED`).
- `POST /api/nikhil/submit-review/`: Submits human analyst review verdict for `Unknown` cases.
- `GET /api/nikhil/investigation/<scan_id>/`: Retrieves full MongoDB Atlas forensic evidence document for UI investigation view.
