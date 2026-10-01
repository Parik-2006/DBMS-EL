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
- **Form Inspection**: Detects password inputs, credit card fields, and external `action` targets.
- **Phishing Heuristics**: Flags cross-domain form submissions, concealed iframes, fake login overlays, and brand name mismatches.

### 3.2 Network, DNS & SSL Analyzer (`NetworkAnalyzer`)
- **Resolution**: Gathers IPv4/IPv6 addresses, reverse DNS PTR records, and MX records.
- **SSL/TLS Validation**: Validates certificate chain, issuer authority, self-signed status, and remaining validity window (flagging newly issued certificates < 14 days old).

### 3.3 Visual Analyzer (`VisualAnalyzer`)
- **Automated Capture**: Uses headless Playwright / Chromium to render the page in a secure sandbox.
- **Storage**: Saves visual evidence to `screenshots/scan_<id>_<timestamp>.png`.
- **Perceptual Image Hash**: Computes difference hash (dHash) to group visually similar phishing kits.

### 3.4 Threat Intelligence Engine (`ThreatIntelService`)
Integrates three verified free community providers plus local database correlation:
- **ThreatFox (`ThreatFoxProvider`)**: Checks domains, IPs, and URLs against abuse.ch ThreatFox IOC database.
- **URLhaus (`URLhausProvider`)**: Queries active malware distribution URLs and payloads.
- **AbuseIPDB (`AbuseIPDBProvider`)**: Assesses IP abuse confidence scores and historical attack reports.
- **Free-Only Guard (`free_only_guard.py`)**: Intercepts requests and enforces hard blocks against commercial paid services (VirusTotal, AlienVault, Shodan, Recorded Future).
- **Trusted Domain Catalog (`TrustedDomainService`)**: Maintains top 10,000 domains (Google, Microsoft, Cloudflare, Instagram, etc.) to immediately dampen false positive alarms on verified platforms.
- **Local SQL Historical Correlation**: Delegates to `HistoricalIntelligenceService` over MySQL models.

### 3.5 Prompt-Injection Detector (`PromptInjectionDetector`)
- Analyzes extracted webpage text and hidden tags for prompt-injection attacks.
- Identifies jailbreak patterns targeting downstream LLMs.
- Strips or neutralizes adversarial text before AI evaluation.

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
1. **Definite Threat**: If ThreatFox or URLhaus returns an active confirmed malware/phishing match $\rightarrow$ immediate threat classification (`HIGH` or `CRITICAL` risk).
2. **Corroborated Threat**: If two or more independent families show strong positive signals $\rightarrow$ classify as `Phishing` / `Malware` / `Defacement`.
3. **Corroborated Benign**: If trusted domain is verified and all collectors report clean status $\rightarrow$ classify as `Benign` (`LOW` risk).
4. **Conflict / Ambiguity**: If signals contradict or evidence is insufficient $\rightarrow$ classify as `Unknown` (`MEDIUM` risk, status `NEEDS_REVIEW`).

---

## 5. API Endpoints

- `POST /api/fallback/result/`: Ingests deep analysis results and updates SQL/MongoDB.
- `GET /api/fallback/uncertain-scans/`: Returns queue of uncertain scans awaiting fallback processing.
- `GET /api/fallback/scan-status/<scan_id>/`: Queries real-time status of a scan (`UNCERTAIN`, `DEEP_ANALYSIS`, `COMPLETED`).
- `POST /api/nikhil/submit-review/`: Submits human analyst review verdict for `Unknown` cases.
- `GET /api/nikhil/investigation/<scan_id>/`: Retrieves full MongoDB Atlas forensic evidence document for UI investigation view.
