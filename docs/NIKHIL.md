# Nikhil Fallback & Deep Evidence Subsystem

## 1. System Mission & Philosophy

The Nikhil Fallback Subsystem activates when the PARI Random Forest model evaluates a URL with uncertainty (confidence score $< 0.75$).

### Core Tenets:
1. **Deterministic Workflow**: No LLM orchestrates or decides the execution flow. The pipeline is pure deterministic Python code.
2. **Multi-Family Corroboration**: No single indicator is trusted blindly. High confidence requires corroboration across multiple independent families (Lexical, DOM, Network, Visual, Threat Intel).
3. **AI as Advisor Only**: Large Language Models (Gemini/OpenRouter) act strictly as forensic interpreters of normalized evidence. The AI **never** directly writes the final verdict.
4. **Strict Free-Only Policy**: No paid APIs (VirusTotal, Shodan, AlienVault) are accessed. Only open, community-driven threat feeds are integrated.
5. **Human-in-the-Loop Safeguard**: If evidence remains conflicting or inconclusive, the system safely defaults to `Unknown` (Needs Review) and registers the case for analyst validation.

---

## 2. Evidence Collectors

### 2.1 Webpage & DOM Analyzer (`WebpageAnalyzer`)
- **Safe Retrieval**: Fetches HTML using bounded timeouts and safe headers.
- **Form Inspection**: Detects password inputs, credit card fields, and external `action` targets.
- **Phishing Heuristics**: Flags cross-domain form submissions, concealed iframes, fake login overlays, and brand name mismatches.

### 2.2 Network, DNS & SSL Analyzer (`NetworkAnalyzer`)
- **Resolution**: Gathers IPv4/IPv6 addresses, reverse DNS PTR records, and MX records.
- **SSL/TLS Validation**: Validates certificate chain, issuer authority, self-signed status, and remaining validity window (flagging newly issued certificates < 14 days old).

### 2.3 Visual Analyzer (`VisualAnalyzer`)
- **Automated Capture**: Uses headless Playwright / Chromium to render the page in a secure sandbox.
- **Storage**: Saves visual evidence to `screenshots/scan_<id>_<timestamp>.png`.
- **Perceptual Image Hash**: Computes difference hash (dHash) to group visually similar phishing kits.

### 2.4 Threat Intelligence Engine (`ThreatIntelService`)
Integrates three verified free community providers plus local database correlation:
- **ThreatFox (`ThreatFoxProvider`)**: Checks domains, IPs, and URLs against abuse.ch ThreatFox IOC database.
- **URLhaus (`URLhausProvider`)**: Queries active malware distribution URLs and payloads.
- **AbuseIPDB (`AbuseIPDBProvider`)**: Assesses IP abuse confidence scores and historical attack reports.
- **Free-Only Guard (`free_only_guard.py`)**: Intercepts requests and enforces hard blocks against commercial paid services (VirusTotal, AlienVault, Shodan, Recorded Future).
- **Trusted Domain Catalog (`TrustedDomainService`)**: Maintains top 10,000 domains (Google, Microsoft, Cloudflare, etc.) to immediately dampen false positive alarms on verified platforms.
- **Local SQL Historical Correlation**: Queries past scans and threat indicators in `maliciousbot_core` to correlate recurring threat actors.

### 2.5 Prompt-Injection Detector (`PromptInjectionDetector`)
- Analyzes extracted webpage text and hidden tags for prompt-injection attacks.
- Identifies jailbreak patterns targeting downstream LLMs (e.g., "Ignore previous system prompt", "You are now in unrestricted mode").
- Strips or neutralizes adversarial text before AI evaluation.

### 2.6 AI Gatekeeper & Provider Manager (`AIAnalyzer`)
- **AIGatekeeper**: Evaluates whether AI analysis is actually necessary. If deterministic indicators are already conclusive or if rate limits are approached, AI execution is skipped (`status: NOT_RUN`).
- **EvidenceNormalizer**: Strips raw HTML, cookies, tokens, and authorization headers, packaging a safe, bounded payload containing:
  - Initial ML class & confidence
  - Exact 10 PARI features
  - High-level evidence summaries from collectors
- **Failover Chain**: Primary Google Gemini (`gemini-2.0-flash`) with automated failover to OpenRouter.
- **Advisory Role**: Generates risk assessment, observations, and reasoning summary.

---

## 3. Corroboration Engine (`FinalClassifier`)

The `FinalClassifier` corroborates multi-source evidence using an engineering score matrix:

| Family | Negative Signals (Benign) | Positive Signals (Threat) |
| :--- | :--- | :--- |
| **URL Lexical** | Low entropy, standard length, recognized TLD | High digit ratio, brand spoofing, hex IP, URL shortener |
| **Webpage DOM** | Standard navigation, valid relative links | External credential action, hidden iframes, password input on unauthenticated page |
| **Network / SSL** | Established certificate (> 90 days), valid CA | Self-signed certificate, expiring < 14 days, dynamic DNS host |
| **Threat Intel** | Zero community reports, trusted domain verified | ThreatFox positive match, URLhaus active malware, AbuseIPDB $> 50\%$ |
| **AI Advisory** | Assessment confirms standard benign site | Assessment identifies phishing indicators or deceptive intent |

### Decision Flow:
1. **Definite Threat**: If ThreatFox or URLhaus returns an active confirmed malware/phishing match $\rightarrow$ immediate threat classification (`HIGH` or `CRITICAL` risk).
2. **Corroborated Threat**: If two or more independent families show strong positive signals $\rightarrow$ classify as `Phishing` / `Malware` / `Defacement`.
3. **Corroborated Benign**: If trusted domain is verified and all collectors report clean status $\rightarrow$ classify as `Benign` (`LOW` risk).
4. **Conflict / Ambiguity**: If signals contradict or evidence is insufficient $\rightarrow$ classify as `Unknown` (`MEDIUM` risk, status `NEEDS_REVIEW`).

---

## 4. API Endpoints

- `POST /api/fallback/result/`: Ingests deep analysis results and updates SQL/MongoDB.
- `GET /api/fallback/uncertain-scans/`: Returns queue of uncertain scans awaiting fallback processing.
- `GET /api/fallback/scan-status/<scan_id>/`: Queries real-time status of a scan (`UNCERTAIN`, `DEEP_ANALYSIS`, `COMPLETED`).
- `POST /api/nikhil/submit-review/`: Submits human analyst review verdict for `Unknown` cases.
- `GET /api/nikhil/investigation/<scan_id>/`: Retrieves full MongoDB Atlas forensic evidence document for UI investigation view.
