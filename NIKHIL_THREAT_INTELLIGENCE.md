# Nikhil Fallback — Free-Only Threat Intelligence Architecture

## 1. Overview & Policy

The **Nikhil Fallback Threat Intelligence Subsystem** integrates free-only, community, and standard-tier external intelligence sources into the six-collector evidence architecture of Nikhil.

### Free-Only Hard Policy
```ini
FREE_ONLY=true
ALLOW_PAID_PROVIDERS=false
```
- **Allowed Providers**:
  1. **ThreatFox Community API** (abuse.ch) — Free under fair-use principles.
  2. **URLhaus Community API** (abuse.ch) — Free under fair-use principles.
  3. **AbuseIPDB Standard Free Tier** — Free standard daily allowance (up to 1,000 checks/day).
  4. **Local SQL Correlation** — PARI schema indicators & historical scans.
  5. **Trusted Domain Intelligence** — Local verified classification (education, government, etc.).
- **Strictly Blocked / Disallowed Providers**:
  - VirusTotal (`virustotal`, `vt`)
  - AlienVault OTX (`alienvault`, `otx`)
  - Commercial / Premium feeds (Shodan, Recorded Future, CrowdStrike, Mandiant, etc.)
  - Any commercial endpoint or paid subscription is blocked by `FreeOnlyGuard` (`CONFIGURATION_BLOCKED`).

---

## 2. Environment Variables & Security

All credentials reside strictly within `.env`, which is permanently git-ignored via `.gitignore`:
```ini
# Threat Intelligence Configuration — Free-Only Policy
THREAT_INTEL_ENABLED=true
FREE_ONLY=true
ALLOW_PAID_PROVIDERS=false
THREATFOX_API_KEY=c44edb...
URLHAUS_API_KEY=c44edb...
ABUSEIPDB_API_KEY=61e713...
```
*(Note: ThreatFox and URLhaus share the official abuse.ch Auth-Key).*

### Security & Sanitization
- **No API keys in source code**: All keys are retrieved via `os.environ`.
- **No API keys in logs**: Provider errors and debug logs never interpolate credentials or authentication headers.
- **No API keys in MongoDB**: The `deep_analysis_cases` collection receives sanitized, structured IOC results only.
- **No API keys in SQL**: Threat indicators stored in `pari_threat_indicator` are pure indicator strings (`DOMAIN:<host>`, `IP_ADDRESS:<ip>`, `REPUTATION:...`), never containing tokens.
- **No API keys in AI payloads**: `EvidenceNormalizer.build_ai_input` extracts high-level counts and statuses only (`threatfox: {status: NO_MATCH, hits: 0}`).

---

## 3. Architecture & Provider Isolation

```
ThreatIntelService
    │
    ├── Local SQL Correlation (Scan, Domain, ThreatIndicator, ScanIndicator)
    ├── Trusted Domain Intelligence (TrustedDomainService)
    ├── FreeOnlyGuard (Enforces free-only policy and blocks commercial endpoints)
    │
    ├── ThreatFoxProvider (abuse.ch Community API — Exact IOC search)
    ├── URLhausProvider (abuse.ch Community API — Malware URL & host search)
    ├── AbuseIPDBProvider (AbuseIPDB v2 API — Public IP reputation)
    │
    ├── Result Normalizer & Aggregator
    └── Final TI Summary
```

### Provider Failure Isolation
Each external query is wrapped in dedicated, bounded exception handlers:
- A failure, timeout, or rate-limit in ThreatFox does **not** stop URLhaus or AbuseIPDB.
- An unavailable external network does **not** stop Local SQL Correlation or Trusted Domain Intelligence.
- Failures degrade gracefully to `PARTIAL` or `UNAVAILABLE`.

---

## 4. Provider Specifications

### A. ThreatFox Community API
- **Endpoint**: `https://threatfox-api.abuse.ch/api/v1/`
- **Authentication**: `Auth-Key: <THREATFOX_API_KEY>`
- **Method**: Exact IOC search (`{"query": "search_ioc", "search_term": "<term>", "exact_match": true}`).
- **Indicators Normalized**: `ioc`, `ioc_type`, `threat_type`, `threat_type_desc`, `malware_printable`, `confidence_level`, `first_seen_utc`, `last_seen_utc`, `tags`.
- **Status Codes**: `SUCCESS`, `NO_MATCH`, `UNAVAILABLE`, `RATE_LIMITED`, `AUTH_ERROR`, `TIMEOUT`, `ERROR`.

### B. URLhaus Community API
- **Endpoints**:
  - URL lookup: `https://urlhaus-api.abuse.ch/v1/url/` (`data={"url": "<url>"}`)
  - Host lookup: `https://urlhaus-api.abuse.ch/v1/host/` (`data={"host": "<host>"}`)
- **Authentication**: `Auth-Key: <URLHAUS_API_KEY>`
- **Purpose**: Detect known malware-distribution infrastructure.
- **Safety**: Never downloads payloads; never executes remote code.
- **Indicators Normalized**: `url`, `threat`, `url_status`, `tags`, `date_added`, `payload_count`.
- **Status Codes**: `SUCCESS`, `NO_MATCH`, `UNAVAILABLE`, `RATE_LIMITED`, `AUTH_ERROR`, `TIMEOUT`, `ERROR`.

### C. AbuseIPDB API (Standard Free Tier)
- **Endpoint**: `https://api.abuseipdb.com/api/v2/check`
- **Authentication**: `Key: <ABUSEIPDB_API_KEY>`, `Accept: application/json`
- **Private IP Guard**: Non-public / RFC 1918 / loopback IPs (`127.0.0.1`, `192.168.x.x`, `10.x.x.x`) are automatically skipped (`SKIPPED_PRIVATE_IP`) to prevent exposing internal infrastructure.
- **Indicators Normalized**: `ip`, `abuseConfidenceScore`, `totalReports`, `numDistinctUsers`, `lastReportedAt`, `countryCode`, `usageType`, `isp`, `isWhitelisted`.
- **Status Codes**: `SUCCESS` (abuse score > 0), `NO_MATCH` (score == 0), `UNAVAILABLE`, `RATE_LIMITED`, `AUTH_ERROR`, `TIMEOUT`, `ERROR`.

---

## 5. Targeted Query Strategy & Deduplication

To preserve free tier quotas and prevent latency bloat:
1. **Local SQL Correlation & Trusted Domain Intelligence**: Always executed.
2. **Domain/URL available**: ThreatFox (domain) + URLhaus (url/host).
3. **Public IP resolved**: AbuseIPDB (ip check) + ThreatFox (IP check if domain had no hit).
4. **Deduplication**: Per-scan query caching ensures identical indicators are never queried twice within the same scan.
5. **Short Bounded Timeouts**: 5.0 seconds per provider with zero aggressive retries.

---

## 6. Meaning of NO_MATCH vs. UNAVAILABLE

A critical architectural distinction:
- **`NO_MATCH`**: The provider was reachable and active, but no known threat indicator matched the query term.
  > **`NO_MATCH` != `CLEAN` / `SAFE`**: The absence of a known IOC in a threat feed does not prove a novel phishing or malware site is safe.
- **`UNAVAILABLE`**: The provider could not be reached (offline, network error, or missing API key).
  > **`UNAVAILABLE` != `CLEAN`**: An unavailable provider produces zero negative weight and does not bias classification toward Benign. Other evidence collectors carry the decision.
- **`RATE_LIMITED`**: The daily quota or burst limit was reached (HTTP 429). The system flags the rate limit and falls back gracefully to other active collectors.

---

## 7. Evidence Corroboration & Classification Integration

Threat Intelligence evidence is fed into **Family 4** of `FinalClassifier`:
- **Malware Support**:
  - URLhaus malware URL hit: `+3.5 Malware`
  - ThreatFox malware IOC hit: `+3.0 Malware`
  - AbuseIPDB high abuse confidence (`>= 75%`): `+2.0 Malware`
- **Phishing Support**:
  - ThreatFox phishing/credential IOC hit: `+3.0 Phishing`
  - AbuseIPDB moderate/high score: `+1.5 Phishing`
- **Benign Support**:
  - Trusted Domain verified category (e.g. Education, Government) + absence of threat hits: `+0.5 to +1.0 Benign`.
  - AbuseIPDB 0% abuse score on valid public IP: `+0.5 Benign`.
- **Corroboration Requirement**: High-severity decisions (`Malware`, `Phishing`) require agreement across at least 2 independent families (e.g. Webpage + Threat Intel, or Network + Threat Intel).

---

## 8. Database Persistence

### MongoDB Atlas (`deep_analysis_cases`)
Stored under `threat_intelligence`:
```json
{
  "status": "SUCCESS",
  "reputation": "CLEAN",
  "sources": {
    "local_sql": { "status": "SUCCESS", "known_malicious_in_domain": 0 },
    "trusted_domain": { "status": "SUCCESS", "is_known": true, "category": "education" },
    "threatfox": { "status": "NO_MATCH", "hits": 0 },
    "urlhaus": { "status": "NO_MATCH", "hits": 0 },
    "abuseipdb": { "status": "NO_MATCH", "abuse_confidence_score": 0 }
  },
  "summary": {
    "known_malicious_ioc": false,
    "known_malware_url": false,
    "ip_abuse_score": 0,
    "positive_hits": 0,
    "sources_available": 3,
    "sources_failed": 0,
    "threat_intel_ui_summary": "SUCCESS · 3 sources checked · No known malicious indicators found"
  }
}
```

### SQL Relational Database (`pari_threat_indicator` & `pari_scan_indicator`)
Meaningful threat indicators detected during fallback are persisted and linked to the `Scan`:
- `indicator_type`: `DOMAIN`, `IP_ADDRESS`, `REPUTATION`, or `OTHER`
- `indicator_value`: `<value>` (e.g. `badhost.com`, `AbuseIPDB score 88%`)
- `severity`: `HIGH` or `CRITICAL` for confirmed external IOCs.

---

## 9. UI Integration

- **Stage 2 (Predict Page)**:
  - Displays dynamic badges (`SUCCESS`, `HITS FOUND (N)`, `PARTIAL`, `RATE LIMITED`, `UNAVAILABLE`).
  - Sub-label displays concise summary: e.g. `SUCCESS · 3 sources checked · No known malicious indicators found`.
- **Stage 3 (Evidence Corroboration)**:
  - Exposes compact badge breakdown: ThreatFox, URLhaus, AbuseIPDB, Local SQL, and Trusted Domain.
- **History View (`data.html`)**:
  - The "Details" button expands an inline panel showing the exact status and reputation scores without exposing any keys.

---

## 10. Verification & Test Summary

- **New TI Test Suite (`test_threat_intel_complete.py`)**: **36 / 36 PASS** (100%)
- **Complete Fallback Test Suite (`test_nikhil_complete.py`)**: **50 / 50 PASS** (100%)
- **Legacy Evidence Test Suite (`test_fallback_evidence.py`)**: **30 / 30 PASS** (100%)
- **Browser Playwright E2E (`test_browser_e2e.py`)**: **6 / 6 PASS** (100%)
- **Live Smoke & NPTEL Validation (`test_live_nptel_and_apis.py`)**:
  - ThreatFox: Connected & Live (200 OK)
  - URLhaus: Connected & Live (200 OK)
  - AbuseIPDB: Connected & Live (200 OK)
  - NPTEL Course URL: Corroborated as Benign (Risk: LOW, Score: 0.11), persisted to MongoDB Atlas & SQL.

---

## 11. Known Limitations

1. **AbuseIPDB Daily Quota**: The free Standard tier allows up to 1,000 checks per 24-hour window. If exhausted, HTTP 429 returns `RATE_LIMITED` and the system continues gracefully using ThreatFox, URLhaus, and local intelligence.
2. **Community Feed Delay**: ThreatFox and URLhaus community databases depend on reporter submissions and sandbox detonations; brand new zero-day phishing infrastructure may not yet be indexed (`NO_MATCH`), which is why multi-family corroboration (DOM + Network analysis) remains mandatory.
3. **Private IP Non-Resolution**: Local intranet or loopback IPs are intentionally skipped from external reputation lookups to prevent leaking internal network topology.
