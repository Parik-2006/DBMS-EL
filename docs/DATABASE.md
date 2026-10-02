# Database Architecture & Schema Specification

## 1. Dual-Database Hybrid Storage Architecture

MaliciousBot implements a production-grade dual-database hybrid architecture where **MySQL** and **MongoDB** have clearly demarcated, complementary roles:

```text
                                 APPLICATION LAYER
                                         │
                    ┌────────────────────┴────────────────────┐
                    ▼                                         ▼
         STRUCTURED RELATIONAL DATA               FLEXIBLE INVESTIGATION CASE
                   MySQL                                    MongoDB
     ┌───────────────────────────────┐         ┌───────────────────────────────┐
     │ - Relational Intelligence     │         │ - Full Deep Analysis Case     │
     │ - Historical Scans & Memory   │         │ - Nested Raw Telemetry        │
     │ - SQL Analytics & Reporting   │         │ - Detailed AI Exchange        │
     │ - Evidence Summaries (Bounded)│         │ - Webpage DOM Snippets        │
     │ - Exact Model Outputs (RF/FB) │         │ - SSL / Network Raw Dumps     │
     │ - Authoritative Final Decisions│        │ - Visual Hash & Screenshots   │
     │ - Multi-Tenant User Isolation │         │                               │
     │ - Zero Duplication of Cases   │         │                               │
     └───────────────────────────────┘         └───────────────────────────────┘
                    ▲                                         ▲
                    └────────────────────┬────────────────────┘
                                   scan_id
                         (Strict 1-to-1 Logical Link)
```

### 1.1 Why MySQL Exists:
- **Structured Relational Intelligence**: High-integrity tables enforcing strict foreign keys, indexes, and unique constraints.
- **Historical Intelligence Memory**: Historical occurrence tracking across exact URLs, domains, IPs, and repeat threat indicators.
- **SQL Analysis & Aggregation**: Complex JOINs, GROUP BY, and statistical queries across hundreds of scans without application-level looping.
- **Structured Evidence & Model Records**: Explicit separation of initial ML (`pari_prediction`), fallback (`pari_scan_fallback`), AI evidence (`pari_ai_evidence`), and official final verdict (`pari_final_decision`).
- **User Isolation & Multi-Tenancy**: Dedicated databases (`maliciousbot_core`, `maliciousbot_guest`, `maliciousbot_user_XXXXXX`) preventing cross-tenant leakage.

### 1.2 Why MongoDB Exists:
- **Full Flexible Investigation Case**: Complete deep-analysis cases containing nested, polymorphic evidence documents.
- **Detailed Forensic Evidence**: Retains entire DOM element trees, network route hops, raw TLS handshake headers, and visual perceptual hash hashes that do not fit into rigid relational tables.
- **Detailed AI Case Information**: Full prompts, gatekeeper evaluations, and model execution metrics.
- **Zero Wholesale Duplication**: MongoDB holds the raw forensic evidence; MySQL holds bounded relational intelligence summaries.

---

## 2. Multi-Tenant User Isolation & Database Structure

Django handles multi-tenancy and guest isolation using `User.db_manager` and `User.db_router`:
1. **`maliciousbot_core` (`default`)**: Master control database; holds `auth_user`, administrative records, and `user_database_registry`.
2. **`maliciousbot_guest` (`guest_db`)**: Dedicated database for unauthenticated guest scans.
3. **`maliciousbot_user_XXXXXX` (`user_<id>`)**: Dynamically registered per-user database for each registered tenant.

---

## 3. Relational Table Catalog (MySQL)

### 3.1 `pari_domain`
- **Purpose**: Normalized domain-level reputation and correlation storage.
- **Key Fields**: `domain_name` (VARCHAR 255, UNIQUE, INDEX), `tld` (VARCHAR 10), `status` (VARCHAR 20, INDEX: BENIGN, SUSPICIOUS, MALICIOUS, UNKNOWN), `risk_score` (FLOAT), `last_scanned` (DATETIME).
- **Relations**: 1-to-many with `pari_url`.
- **Written by**: URL ingestion pipeline.
- **Read by**: Domain intelligence, ML feature extraction, `HistoricalIntelligenceService`.

### 3.2 `pari_url`
- **Purpose**: Normalized URL entity deduplication across all scans.
- **Key Fields**: `url` (VARCHAR 500, UNIQUE, INDEX), `domain_id` (FK -> `pari_domain`), `source` (VARCHAR 20: BASELINE, USER_SCAN, CORRELATION), `baseline_label` (VARCHAR 20).
- **Relations**: Many-to-1 with `pari_domain`; 1-to-many with `pari_scan`.
- **Written by**: Scan initiation.
- **Read by**: Scan lookup, history lookups, ML services.

### 3.3 `pari_ip`
- **Purpose**: Normalized IP address catalog for network correlation.
- **Key Fields**: `ip_address` (GenericIPAddress, UNIQUE, INDEX), `status` (VARCHAR 20), `country` (VARCHAR 100), `risk_score` (FLOAT).
- **Relations**: Referenced by network correlation and threat indicators.
- **Written by**: `NetworkAnalyzer`.
- **Read by**: `HistoricalIntelligenceService`.

### 3.4 `pari_scan`
- **Purpose**: Represents a single URL analysis execution transaction.
- **Key Fields**: `id` (INT PK), `user_id` (FK -> `auth_user`, db_constraint=False), `url_id` (FK -> `pari_url`), `status` (VARCHAR 20, INDEX: CONFIDENT, UNCERTAIN, DEEP_ANALYSIS, COMPLETED, ERROR), `initial_model` (VARCHAR 50), `fallback_model` (VARCHAR 50), `created_at` (DATETIME, INDEX).
- **Relations**: Parent entity for prediction, features, fallback, summaries, AI evidence, final decision.
- **Written by**: Core scan coordinator.
- **Read by**: All scanning, history, and reporting pipelines.

### 3.5 `pari_scan_features` (Phase 2)
- **Purpose**: Permanent record of the exact 10 numeric/categorical features extracted for the RandomForest classifier.
- **Key Fields**:
  - `scan_id` (OneToOne -> `pari_scan`, CASCADE)
  - `url_len` (INT), `letters_count` (INT), `digits_count` (INT), `special_chars_count` (INT)
  - `shortened` (SmallInt), `abnormal_url` (SmallInt), `secure_http` (SmallInt), `have_ip` (SmallInt)
  - `url_region` (BigInt), `root_domain` (BigInt)
- **Indexes**: `(have_ip)`, `(secure_http)`, `(shortened)`, `(have_ip, secure_http)`.
- **Written by**: `MLPredictionService`.
- **Read by**: ML inference, suspicious-feature query analytics.

### 3.6 `pari_prediction` (Phase 3 Separation)
- **Purpose**: Permanent record of the INITIAL RandomForest ML prediction. NEVER overwritten by fallback.
- **Key Fields**: `scan_id` (OneToOne -> `pari_scan`, CASCADE), `model_name` ('RandomForest'), `predicted_class` (VARCHAR 20, INDEX), `confidence` (FLOAT, INDEX), `risk_score` (FLOAT, INDEX), `threshold_used` (FLOAT: 0.75), `is_confident` (BOOLEAN, INDEX).
- **Written by**: `MLPredictionService`.
- **Read by**: Routing engine, reporting layer, historical intelligence.

### 3.7 `pari_scan_fallback` (Phase 3 Separation)
- **Purpose**: Stores the DeepAnalysis / Nikhil fallback execution outcome for scans that were UNCERTAIN.
- **Key Fields**: `scan_id` (OneToOne -> `pari_scan`, CASCADE), `service_name` ('DeepAnalysis'), `classification` (VARCHAR 20, INDEX), `risk_score` (FLOAT, INDEX), `risk_level` (VARCHAR 20, INDEX), `evidence_summary` (VARCHAR 500), `mongo_document_reference` (VARCHAR 100).
- **Written by**: `FallbackIntegrationService`.
- **Read by**: Reporting layer, investigation views, historical intelligence.

### 3.8 `pari_evidence_summary` (Phase 4)
- **Purpose**: Compact structured evidence summary per evidence family for a scan.
- **Key Fields**: `scan_id` (FK -> `pari_scan`), `evidence_family` (VARCHAR 50, INDEX: WEBPAGE, NETWORK, VISUAL, THREAT_INTELLIGENCE, PROMPT_INJECTION, SQL_HISTORY, TRUSTED_DOMAIN), `status` (VARCHAR 30), `detected` (BOOLEAN), `match_found` (BOOLEAN), `evidence_count` (INT), `severity` (VARCHAR 20), `summary` (VARCHAR 500), `source_component` (VARCHAR 100).
- **Constraints**: `UniqueConstraint(fields=['scan', 'evidence_family'])`.
- **Written by**: `FallbackIntegrationService.persist_evidence_summaries`.
- **Read by**: Explainability service, DBMS reporting layer.

### 3.9 `pari_ai_evidence` (Phase 5)
- **Purpose**: Safe, compact summary of AI advisory evidence for a scan.
- **Key Fields**: `scan_id` (OneToOne -> `pari_scan`, CASCADE), `provider` (VARCHAR 50), `model` (VARCHAR 100), `status` (VARCHAR 30, INDEX: NOT_RUN, SUCCESS, UNAVAILABLE, etc.), `assessment` (VARCHAR 50, INDEX), `confidence` (FLOAT), `risk_score` (FLOAT), `ai_required` (BOOLEAN, INDEX), `ai_called` (BOOLEAN, INDEX), `reasoning_summary` (VARCHAR 500).
- **Written by**: `FallbackIntegrationService.persist_ai_evidence`.
- **Read by**: Reporting layer, explainability service. AI is NEVER the final authority.

### 3.10 `pari_threat_indicator` (Phase 8)
- **Purpose**: Shared catalog of discrete threat indicators and IOC patterns.
- **Key Fields**: `indicator_type` (VARCHAR 30, INDEX), `indicator_value` (VARCHAR 255), `severity` (VARCHAR 10, INDEX: LOW, MEDIUM, HIGH, CRITICAL).
- **Constraints**: `unique_together = ('indicator_type', 'indicator_value')`.
- **Written by**: Threat collectors and analyzers.
- **Read by**: Indicator intelligence, pattern co-occurrence queries.

### 3.11 `pari_scan_indicator` (Phase 8 & 9)
- **Purpose**: Junction table linking scans to indicators with provenance metadata.
- **Key Fields**: `scan_id` (FK -> `pari_scan`), `indicator_id` (FK -> `pari_threat_indicator`), `source_component` (VARCHAR 100, INDEX), `reason` (VARCHAR 500), `severity` (VARCHAR 10), `detected_at` (DATETIME).
- **Constraints**: `unique_together = ('scan', 'indicator')`.
- **Written by**: `FallbackIntegrationService.persist_threat_indicators`.
- **Read by**: Provenance reports, co-occurrence analytics, explainability engine.

### 3.12 `pari_final_decision` (Phase 10)
- **Purpose**: Authoritative final classification and risk decision established by deterministic corroboration or confident ML.
- **Key Fields**: `scan_id` (OneToOne -> `pari_scan`, CASCADE), `final_classification` (VARCHAR 20, INDEX), `risk_score` (FLOAT, INDEX), `risk_level` (VARCHAR 20, INDEX), `decision_status` (VARCHAR 30: FINAL, CONFIDENT_ML, NEEDS_REVIEW, OVERRIDDEN), `decision_method` (VARCHAR 50: DETERMINISTIC_CORROBORATION, INITIAL_ML), `corroboration_strength` (VARCHAR 30), `evidence_family_count` (INT), `conflict_detected` (BOOLEAN, INDEX), `decision_summary` (VARCHAR 500), `decision_timestamp` (DATETIME, INDEX).
- **Written by**: `FallbackIntegrationService.persist_final_decision` & `MLPredictionService`.
- **Read by**: UI, reporting layer, user history listings.

### 3.13 `pari_analyst_review`
- **Purpose**: Human-in-the-loop analyst validation records for `Unknown` / `Needs Review` cases.
- **Key Fields**: `scan_id` (OneToOne -> `pari_scan`), `reviewer_id` (FK -> `auth_user`), `final_label` (VARCHAR 20), `review_notes` (TEXT), `validation_status` (VARCHAR 20).
- **Written by**: Security analysts via `/api/nikhil/submit-review/`.
- **Read by**: Model retraining pipelines and historical intelligence.

### 3.14 `history_clear_events`
- **Purpose**: Non-destructive history clear boundary records.
- **Key Fields**: `user_id` (INT, NULLABLE), `cleared_at` (DATETIME, INDEX).
- **Semantics**: Hides scans created prior to `cleared_at` from user history listings while permanently preserving all underlying relational data.

### 3.15 `user_database_registry`
- **Purpose**: Master multi-tenant mapping stored in `maliciousbot_core`.
- **Key Fields**: `user_id` (INT UNIQUE), `username` (VARCHAR 150), `database_name` (VARCHAR 100 UNIQUE), `status` (VARCHAR 30).

---

## 4. AI & Model Evidence Separation Principles

The system strictly enforces the following semantic separations:

1. **RF Confidence $\neq$ AI Confidence $\neq$ Fallback Risk $\neq$ Final Risk**:
   - `Prediction.confidence`: Softmax probability (0.0 to 1.0) from the 10-feature RandomForest model.
   - `ScanAIEvidence.confidence`: Forensic confidence score reported by Gemini/OpenRouter advisory model.
   - `ScanFallbackResult.risk_score`: Aggregated score computed across deterministic deep analyzers.
   - `ScanFinalDecision.risk_score`: Official final corroborated risk score.
2. **AI Assessment $\neq$ Final Classification**:
   - The AI assessment is purely an advisory evidence signal (`ScanAIEvidence.assessment`).
   - The final classification (`ScanFinalDecision.final_classification`) is computed by deterministic Python corroboration logic (`FinalClassifier`).
   - In cases of conflict, the system defaults to `Unknown` (`NEEDS_REVIEW`) rather than blindly following AI.

---

## 5. Security & Privacy Guarantees

1. **No Secret Persistence**: API keys, bearer tokens, passwords, cookies, and authorization headers are strictly excluded from MySQL and MongoDB.
2. **No Raw LLM Prompts / Private CoT**: Chain-of-thought and raw prompt payloads are not persisted in MySQL.
3. **Multi-Tenant User Isolation**: Every registered user operates within an isolated database instance; guest scans are isolated in `maliciousbot_guest`.
4. **Free-Only AI Policy**: Paid AI providers are unconditionally blocked by `free_only_guard.py`.

---

## 6. Representative DBMS Demonstration Queries

All queries are implemented in `User/services/dbms_reporting_service.py` (`DBMSReportingService`):

### Query 1: Initial ML Uncertainty Scans
```sql
SELECT s.id AS scan_id, u.url, p.predicted_class AS initial_class, p.confidence, p.threshold_used, p.is_confident
FROM pari_prediction p
JOIN pari_scan s ON p.scan_id = s.id
JOIN pari_url u ON s.url_id = u.id
WHERE p.confidence < 0.75 OR p.is_confident = 0
ORDER BY p.confidence ASC
LIMIT 100;
```

### Query 2: Initial vs Final Decision Disagreement
```sql
SELECT s.id AS scan_id, u.url, p.predicted_class AS initial_rf_class, p.confidence AS initial_confidence,
       fd.final_classification, fd.risk_score AS final_risk, fd.decision_method
FROM pari_final_decision fd
JOIN pari_scan s ON fd.scan_id = s.id
JOIN pari_url u ON s.url_id = u.id
JOIN pari_prediction p ON p.scan_id = s.id
WHERE p.predicted_class != fd.final_classification
ORDER BY s.id DESC
LIMIT 100;
```

### Query 3: AI Assessment vs Final Classification Disagreement
```sql
SELECT s.id AS scan_id, u.url, ai.assessment AS ai_assessment, ai.confidence AS ai_confidence,
       fd.final_classification, fd.decision_method AS final_decision_method, fd.risk_score
FROM pari_ai_evidence ai
JOIN pari_scan s ON ai.scan_id = s.id
JOIN pari_url u ON s.url_id = u.id
JOIN pari_final_decision fd ON fd.scan_id = s.id
WHERE ai.assessment IS NOT NULL
  AND UPPER(REPLACE(ai.assessment, 'LIKELY_', '')) != UPPER(fd.final_classification)
ORDER BY s.id DESC
LIMIT 100;
```

### Query 4: Distinct Evidence Family Counts
```sql
SELECT s.id AS scan_id, u.url, COUNT(DISTINCT ev.evidence_family) AS distinct_family_count,
       GROUP_CONCAT(DISTINCT ev.evidence_family ORDER BY ev.evidence_family SEPARATOR ', ') AS families_list
FROM pari_scan s
JOIN pari_url u ON s.url_id = u.id
JOIN pari_evidence_summary ev ON ev.scan_id = s.id
GROUP BY s.id, u.url
ORDER BY distinct_family_count DESC, s.id DESC
LIMIT 100;
```

### Query 5: Threat Indicator Frequency
```sql
SELECT ti.id AS indicator_id, ti.indicator_type, ti.indicator_value, ti.severity,
       COUNT(si.id) AS occurrence_count,
       COUNT(DISTINCT s.url_id) AS distinct_url_count,
       COUNT(DISTINCT u.domain_id) AS distinct_domain_count
FROM pari_threat_indicator ti
JOIN pari_scan_indicator si ON si.indicator_id = ti.id
JOIN pari_scan s ON si.scan_id = s.id
JOIN pari_url u ON s.url_id = u.id
GROUP BY ti.id, ti.indicator_type, ti.indicator_value, ti.severity
ORDER BY occurrence_count DESC, ti.id ASC
LIMIT 100;
```

### Query 6: Threat Indicator Co-occurrence
```sql
SELECT CONCAT(ti1.indicator_type, ':', ti1.indicator_value) AS indicator_a,
       CONCAT(ti2.indicator_type, ':', ti2.indicator_value) AS indicator_b,
       COUNT(DISTINCT si1.scan_id) AS cooccurrence_count
FROM pari_scan_indicator si1
JOIN pari_scan_indicator si2 ON si1.scan_id = si2.scan_id AND si1.indicator_id < si2.indicator_id
JOIN pari_threat_indicator ti1 ON si1.indicator_id = ti1.id
JOIN pari_threat_indicator ti2 ON si2.indicator_id = ti2.id
GROUP BY si1.indicator_id, si2.indicator_id, ti1.indicator_type, ti1.indicator_value, ti2.indicator_type, ti2.indicator_value
ORDER BY cooccurrence_count DESC
LIMIT 100;
```

### Query 7: Mixed-History Domains
```sql
SELECT d.id AS domain_id, d.domain_name,
       COUNT(DISTINCT COALESCE(fd.final_classification, fb.classification, p.predicted_class)) AS distinct_class_count,
       GROUP_CONCAT(DISTINCT COALESCE(fd.final_classification, fb.classification, p.predicted_class) SEPARATOR ', ') AS classification_distribution,
       COUNT(s.id) AS total_scans
FROM pari_domain d
JOIN pari_url u ON u.domain_id = d.id
JOIN pari_scan s ON s.url_id = u.id
LEFT JOIN pari_final_decision fd ON fd.scan_id = s.id
LEFT JOIN pari_scan_fallback fb ON fb.scan_id = s.id
LEFT JOIN pari_prediction p ON p.scan_id = s.id
GROUP BY d.id, d.domain_name
HAVING distinct_class_count > 1
ORDER BY distinct_class_count DESC, total_scans DESC
LIMIT 100;
```

### Query 8: Suspicious Feature Combinations
```sql
SELECT s.id AS scan_id, u.url, sf.have_ip, sf.secure_http, sf.shortened, sf.abnormal_url, sf.url_len,
       COALESCE(fd.final_classification, p.predicted_class) AS classification,
       COALESCE(fd.risk_score, p.risk_score) AS risk_score
FROM pari_scan_features sf
JOIN pari_scan s ON sf.scan_id = s.id
JOIN pari_url u ON s.url_id = u.id
LEFT JOIN pari_prediction p ON p.scan_id = s.id
LEFT JOIN pari_final_decision fd ON fd.scan_id = s.id
WHERE (sf.have_ip = 1 AND sf.secure_http = 0)
   OR (sf.shortened = 1 AND sf.abnormal_url = 1)
ORDER BY s.id DESC
LIMIT 100;
```

### Query 9: Evidence Provenance Report
```sql
SELECT evidence_family, source_component, 'EVIDENCE_FAMILY' AS evidence_kind, status, severity, summary AS description
FROM pari_evidence_summary
WHERE scan_id = %s
UNION ALL
SELECT ti.indicator_type AS evidence_family, si.source_component, 'THREAT_INDICATOR' AS evidence_kind, 'DETECTED' AS status,
       COALESCE(si.severity, ti.severity) AS severity,
       CONCAT(ti.indicator_value, CASE WHEN si.reason != '' THEN CONCAT(' (', si.reason, ')') ELSE '' END) AS description
FROM pari_scan_indicator si
JOIN pari_threat_indicator ti ON si.indicator_id = ti.id
WHERE si.scan_id = %s;
```

### Query 10: Full Scan Investigation Overview
```sql
SELECT s.id AS scan_id, u.url, d.domain_name, s.status AS scan_status, s.created_at,
       p.predicted_class AS initial_rf_class, p.confidence AS initial_rf_confidence,
       fb.classification AS fallback_classification, fb.risk_score AS fallback_risk_score,
       ai.status AS ai_status, ai.assessment AS ai_assessment,
       fd.final_classification, fd.risk_score AS final_risk_score, fd.risk_level AS final_risk_level,
       fd.decision_method AS final_decision_method, fd.corroboration_strength, fd.evidence_family_count, fd.conflict_detected
FROM pari_scan s
JOIN pari_url u ON s.url_id = u.id
LEFT JOIN pari_domain d ON u.domain_id = d.id
LEFT JOIN pari_prediction p ON p.scan_id = s.id
LEFT JOIN pari_scan_fallback fb ON fb.scan_id = s.id
LEFT JOIN pari_ai_evidence ai ON ai.scan_id = s.id
LEFT JOIN pari_final_decision fd ON fd.scan_id = s.id
WHERE s.id = %s;
```
