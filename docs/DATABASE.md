# Database Architecture & Schema Specification

## 1. Dual-Database Hybrid Storage Model

MaliciousBot implements a hybrid database architecture:
1. **MySQL Relational Database**: Handles strict transactional consistency, normalized entities (domains, URLs, IPs, scans, predictions, users), relational constraints, foreign keys, and multi-tenant user isolation.
2. **MongoDB Atlas Document Database**: Handles heterogeneous, multi-module deep investigation evidence (webpage DOM snippets, SSL certificates, network findings, threat intel feeds, AI rationales, perceptual visual hashes) with dynamic schema requirements.

```
+-----------------------------------------------------------------------------------+
|                                 APPLICATION LAYER                                 |
+-----------------------------------------------------------------------------------+
           |                                                      |
           v (Structured Relational Data)                         v (Unstructured Evidence)
+------------------------------------+                 +------------------------------------+
|               MySQL                |                 |           MongoDB Atlas            |
| - maliciousbot_core (Auth users)   |                 | - Database: nikhil_db              |
| - maliciousbot_guest (Guest scans) |                 | - Collection: deep_analysis_cases  |
| - Logical Link: scan_id            | <=============> | - Logical Link: scan_id            |
+------------------------------------+                 +------------------------------------+
```

---

## 2. MySQL Relational Database Architecture

### 2.1 Multi-Tenant Routing
Django handles multi-tenancy and guest isolation using `User.db_router.UserDatabaseRouter`:
- **`default` (`maliciousbot_core`)**: Stores registered users, administrative data, authenticated scans, analyst reviews, and user registration records.
- **`guest_db` (`maliciousbot_guest`)**: Stores unauthenticated guest scans to isolate public or untrusted traffic from core user databases.

### 2.2 Relational Schema Definitions

#### 1. `pari_domain`
Normalized domain storage for reputation and aggregate risk scoring.
- `id` (INT, PK, AUTO_INCREMENT)
- `domain_name` (VARCHAR(255), UNIQUE, INDEX)
- `tld` (VARCHAR(10), NULLABLE)
- `status` (VARCHAR(20), DEFAULT 'UNKNOWN', INDEX: BENIGN, SUSPICIOUS, MALICIOUS, UNKNOWN)
- `risk_score` (FLOAT, DEFAULT 0.0, INDEX)
- `last_scanned` (DATETIME, NULLABLE)
- `created_at` / `updated_at` (DATETIME)

#### 2. `pari_url`
Normalized URL storage ensuring deduplication across scans.
- `id` (INT, PK, AUTO_INCREMENT)
- `url` (VARCHAR(500), UNIQUE, INDEX)
- `domain_id` (INT, FK -> `pari_domain.id`, ON DELETE CASCADE, INDEX)
- `source` (VARCHAR(20), DEFAULT 'USER_SCAN': BASELINE, USER_SCAN, CORRELATION)
- `baseline_label` (VARCHAR(20), NULLABLE: benign, defacement, phishing, malware)
- `created_at` (DATETIME)

#### 3. `pari_ip`
Normalized IP resolution storage for network-level correlation.
- `id` (INT, PK, AUTO_INCREMENT)
- `ip_address` (VARCHAR(39), UNIQUE, INDEX: IPv4 / IPv6)
- `status` (VARCHAR(20), DEFAULT 'UNKNOWN', INDEX)
- `country` (VARCHAR(100), NULLABLE)
- `risk_score` (FLOAT, DEFAULT 0.0, INDEX)
- `created_at` / `updated_at` (DATETIME)

#### 4. `pari_scan`
Represents an individual scan execution.
- `id` (INT, PK, AUTO_INCREMENT)
- `user_id` (INT, NULLABLE, FK -> `auth_user.id`, ON DELETE CASCADE)
- `url_id` (INT, FK -> `pari_url.id`, ON DELETE CASCADE)
- `status` (VARCHAR(20), INDEX: CONFIDENT, UNCERTAIN, DEEP_ANALYSIS, COMPLETED, ERROR)
- `initial_model` (VARCHAR(50), DEFAULT 'RandomForest')
- `fallback_model` (VARCHAR(50), NULLABLE)
- `created_at` / `updated_at` / `completed_at` (DATETIME)

#### 5. `pari_prediction`
Stores the ML prediction and probability distribution for a scan.
- `id` (INT, PK, AUTO_INCREMENT)
- `scan_id` (INT, UNIQUE, FK -> `pari_scan.id`, ON DELETE CASCADE)
- `model_name` (VARCHAR(50))
- `predicted_class` (VARCHAR(20), INDEX: Benign, Phishing, Malware, Defacement, Unknown)
- `confidence` (FLOAT, INDEX)
- `risk_score` (FLOAT, INDEX)
- `probabilities` (JSON: `{"Benign": float, "Defacement": float, "Phishing": float, "Malware": float}`)
- `created_at` / `updated_at` (DATETIME)

#### 6. `pari_threat_indicator`
Catalog of observed threat signals and IOCs.
- `id` (INT, PK, AUTO_INCREMENT)
- `indicator_type` (VARCHAR(50): IP_ADDRESS, DOMAIN, URL_LENGTH, SPECIAL_CHARS, SHORTENER, SSL_CERTIFICATE, THREATFOX_HIT, URLHAUS_HIT, ABUSEIPDB_HIT)
- `value` (VARCHAR(500))
- `severity` (VARCHAR(20): LOW, MEDIUM, HIGH, CRITICAL)
- `description` (TEXT)
- UNIQUE constraint on `(indicator_type, value(255))`

#### 7. `pari_scan_indicator`
Many-to-many junction linking scans to observed threat indicators.
- `id` (INT, PK, AUTO_INCREMENT)
- `scan_id` (INT, FK -> `pari_scan.id`, ON DELETE CASCADE)
- `indicator_id` (INT, FK -> `pari_threat_indicator.id`, ON DELETE CASCADE)
- `observed_at` (DATETIME)
- UNIQUE constraint on `(scan_id, indicator_id)`

#### 8. `pari_analyst_review`
Supports human-in-the-loop analyst review for `Unknown` / `Needs Review` scans.
- `id` (INT, PK, AUTO_INCREMENT)
- `scan_id` (INT, UNIQUE, FK -> `pari_scan.id`, ON DELETE CASCADE)
- `reviewer_id` (INT, NULLABLE, FK -> `auth_user.id`)
- `reviewed_at` (DATETIME)
- `final_label` (VARCHAR(20): Benign, Phishing, Malware, Defacement, Still Unknown)
- `review_notes` (TEXT)
- `validation_status` (VARCHAR(20): VALIDATED, NOT_VALIDATED)

---

## 3. MongoDB Atlas Document Storage

### 3.1 Configuration & Connection Resilience
- **Database**: `nikhil_db` (configurable via `MONGODB_DATABASE`)
- **Collection**: `deep_analysis_cases` (configurable via `MONGODB_COLLECTION`)
- **Index**: Unique index on `scan_id`.
- **Fault-Tolerance**: If MongoDB Atlas is temporarily unreachable, `MongoDBRepository` automatically falls back to an in-memory cache (`_fallback_cache`) ensuring the scan pipeline never crashes.

### 3.2 Document Structure (`deep_analysis_cases`)

```json
{
  "_id": "6abd15eef46c30ddb0b8876a",
  "scan_id": 90,
  "url": "https://suspicious-site.com/login",
  "analysis_status": "COMPLETED",

  "initial_ml": {
    "class": "Phishing",
    "confidence": 0.6245995124117073,
    "pari_features": {
      "url_len": 32,
      "letters_count": 25,
      "digits_count": 0,
      "special_chars_count": 7,
      "shortened": 0,
      "abnormal_url": 1,
      "secure_http": 1,
      "have_ip": 0,
      "url_region": 32604616,
      "root_domain": 51955043
    }
  },

  "webpage": {
    "status": "SUCCESS",
    "title": "Account Verification",
    "form_count": 1,
    "has_password_form": true,
    "cross_domain_forms": true,
    "findings": ["External credential POST action detected"]
  },

  "network": {
    "status": "SUCCESS",
    "ip_resolution": {
      "primary_ip": "198.51.100.24",
      "all_ips": ["198.51.100.24"]
    },
    "ssl_tls": {
      "valid": true,
      "issuer": "Let's Encrypt",
      "days_until_expiry": 14
    }
  },

  "visual": {
    "status": "SUCCESS",
    "screenshot_path": "screenshots/scan_90_1790253857.png",
    "image_hash": "a1b2c3d4e5f60718"
  },

  "threat_intelligence": {
    "status": "SUCCESS",
    "summary": {
      "positive_hits": 1,
      "sources_available": 3
    },
    "sources": {
      "threatfox": {"status": "MATCH", "hits": 1, "confidence": 90},
      "urlhaus": {"status": "NO_MATCH", "hits": 0},
      "abuseipdb": {"status": "SUCCESS", "abuse_confidence_score": 75}
    },
    "trusted_domain": {
      "is_known": false,
      "category": null
    },
    "url_features": {
      "domain_length": 19,
      "entropy": 3.8
    }
  },

  "prompt_injection": {
    "prompt_injection_detected": false,
    "matched_patterns": [],
    "confidence": 0.0
  },

  "ai_analysis": {
    "status": "SUCCESS",
    "ai_required": true,
    "ai_called": true,
    "provider": "google_gemini",
    "model": "gemini-2.0-flash",
    "assessment": "High probability credential harvesting phishing site.",
    "reasoning_summary": "Form targets external domain while presenting brand login visuals.",
    "authoritative": false
  },

  "corroboration": {
    "strength": "STRONG",
    "corroborating_families": ["webpage", "threat_intelligence"],
    "score": 0.88
  },

  "final_analysis": {
    "classification": "Phishing",
    "risk_level": "HIGH",
    "risk_score": 0.90,
    "evidence_summary": "Phishing confirmed across DOM credential harvesting indicators and ThreatFox intelligence."
  },

  "timestamps": {
    "started_at": 1790253850.12,
    "completed_at": 1790253854.45,
    "duration_seconds": 4.33
  }
}
```

---

## 4. Logical Linkage: SQL <-> MongoDB

The relational MySQL database and MongoDB Atlas collection maintain a strict 1-to-1 logical link via `scan_id`:
- `pari_scan.id` in MySQL == `deep_analysis_cases.scan_id` in MongoDB.
- Quick user queries, history listings, and status checks query MySQL.
- Detailed investigation views, forensic evidence drill-downs, and API endpoints (`GET /api/nikhil/investigation/<scan_id>/`) retrieve the document from MongoDB Atlas.
