# PARI — Implementation Plan & Prompts

## Project Goal
Implement the structured/relational side of the malicious URL detection project while preserving the existing 400-URL baseline ML system.

## Architecture We Are Building

400 labelled URLs
→ existing feature extraction
→ Random Forest + Logistic Regression
→ confidence check
→ confident result → MySQL
→ uncertain result → handoff to Nikhil's fallback system

Nikhil's fallback system will perform deep analysis, use MongoDB for flexible evidence, and return the final evidence/result back to the structured MySQL layer.

---

# PROMPT 1 — Baseline Audit and Freeze

### Description
Understand the existing project before changing anything. The existing 400 labelled URLs, feature extraction, Random Forest, Logistic Regression fallback, four classes, and current application flow are the baseline and must not be unnecessarily changed.

### Prompt
```text
You are responsible for the structured/ML side of our existing malicious URL detection project.

Before implementing anything, inspect the complete codebase carefully.

IMPORTANT:
- Do NOT replace the existing ML system.
- Do NOT remove or modify the existing 400 labelled URL dataset.
- Do NOT change the existing train/test split unless absolutely necessary for integration.
- Preserve the existing Random Forest primary model and Logistic Regression fallback.
- Preserve the four classes: Benign, Phishing, Malware, Defacement.

Your task is to audit the codebase and create ARCHITECTURE_BASELINE.md containing:
1. Current project structure.
2. Dataset location and format.
3. Feature extraction implementation.
4. Random Forest implementation.
5. Logistic Regression implementation.
6. Current prediction/inference flow.
7. Current database usage.
8. Current API/backend endpoints related to scanning.
9. Current frontend pages related to scanning/history.
10. Existing limitations relevant to our new architecture.
11. Files that must be modified for the MySQL/confidence layer.
12. Files that should be left untouched.

Do not implement the new MySQL schema yet.
Do not implement MongoDB or fallback analysis.
Keep code changes to a minimum; this step is an audit/freeze step.

At the end, provide a concise summary and list the exact files proposed for the next steps.
```

---

# PROMPT 2 — MySQL Relational Schema

### Description
Build the main relational database. MySQL will store structured data, relationships, history, prediction results, and threat indicators.

### Prompt
```text
Now implement the structured SQL/MySQL database layer for the malicious URL detection system.

IMPORTANT:
- Do not break the existing ML pipeline.
- Do not modify the 400-URL training/testing logic.
- Do not implement MongoDB in this step.

Create a normalized relational schema containing at minimum:
1. users
2. domains
3. urls
4. ips
5. scans
6. predictions
7. threat_indicators
8. scan_indicators

Required relationships:
- users 1→many scans
- domains 1→many urls
- urls 1→many scans
- ips 1→many scans
- scans 1→many predictions
- scans many↔many threat_indicators through scan_indicators

Use:
- Primary keys
- Foreign keys
- UNIQUE constraints where appropriate
- NOT NULL where appropriate
- CHECK constraints where supported and appropriate
- Indexes for frequently searched fields
- Timestamps for important records
- Normalization to reduce redundancy

Prediction classes:
- Benign
- Phishing
- Malware
- Defacement

Scan statuses must support at least:
- CONFIDENT
- UNCERTAIN
- DEEP_ANALYSIS
- COMPLETED

Prediction records should support:
- model_name
- predicted_class
- confidence
- risk_score
- timestamp

Use the project's existing ORM/migration mechanism where possible.

At the end:
1. List changed files.
2. Show the final relational schema.
3. Explain each table briefly.
4. Run migrations/tests.
5. Confirm existing application functionality still works.
```

---

# PROMPT 3 — Import the 400 Baseline URLs into MySQL

### Description
Represent the existing 400 labelled URLs in MySQL without changing the existing ML training/testing dataset or labels.

### Prompt
```text
Now import the existing 400 labelled URLs into the MySQL database.

IMPORTANT:
- The existing dataset remains the ML baseline.
- Do NOT change the existing 70/30 train-test split.
- Do NOT retrain or redesign the model.
- Do NOT automatically add new user scans to the training dataset.

Tasks:
1. Read the existing 400 labelled URL dataset.
2. Preserve every original label exactly:
   Benign / Phishing / Malware / Defacement.
3. Import the URLs into the SQL database.
4. Create normalized domain records.
5. Avoid duplicate URLs and duplicate domains.
6. Make the import idempotent.
7. Clearly distinguish baseline dataset records from user-submitted scan records.
8. Preserve the original source/reference information where available.

Use a suitable source field or equivalent relational design, for example:
- BASELINE_DATASET
- USER_SCAN

After importing, verify and report:
- total URLs imported
- total domains
- count per class
- duplicate count prevented
- database integrity

Do not implement MongoDB or fallback analysis in this step.
```

---

# PROMPT 4 — Confidence Check and Unknown/Uncertain Routing

### Description
Add the new runtime decision layer. The first-stage model should classify confidently when possible and explicitly route uncertain cases instead of forcing a class.

### Prompt
```text
Now implement the runtime confidence and uncertain-case routing layer.

Existing model hierarchy must remain:
1. Random Forest = primary model
2. Logistic Regression = model-level fallback if Random Forest is unavailable or cannot produce a usable prediction

New runtime flow:
User submits NEW URL
→ existing feature extraction
→ Random Forest prediction
→ confidence check

If confidence >= configurable threshold:
    mark scan CONFIDENT
    store structured prediction in MySQL
    return direct result

If Random Forest fails:
    use Logistic Regression

If the available prediction remains below the configured confidence threshold:
    mark scan UNCERTAIN
    do NOT force a final class
    create a clean handoff for the fallback/deep-analysis system owned by another team member

IMPORTANT:
- "UNCERTAIN" means insufficient model confidence; it does not mean malicious.
- Do not automatically add uncertain cases to the training dataset.
- Keep the threshold configurable in one place.
- Store model name, class, confidence, scan status and timestamp in MySQL.
- Preserve existing normal prediction behaviour where possible.

Create a clear service/API contract for the fallback handoff, including at minimum:
- scan_id
- url_id or URL
- initial_predicted_class, if available
- initial_confidence
- scan_status

Do not implement webpage scraping, LLM analysis or MongoDB in this step.

Test:
1. confident case
2. low-confidence case
3. Random Forest failure → Logistic Regression
4. invalid URL
5. duplicate URL
```

---

# PROMPT 5 — SQL Correlation, Final Result Storage, and Integration

### Description
Make MySQL the structured source of truth for security relationships and final scan results. Integrate the fallback result returned by Nikhil's modules without taking over their deep-analysis implementation.

### Prompt
```text
Now implement the structured correlation and final-result integration layer using MySQL.

MySQL is responsible for:
- structured scan records
- URLs
- domains
- IPs
- predictions
- threat indicators
- relationships
- history
- final structured results

Implement SQL-backed investigation queries/services such as:
1. URLs belonging to the same domain.
2. Domains sharing the same IP.
3. IPs associated with multiple malicious URLs.
4. Domain scan history.
5. Historical prediction changes for a domain.
6. Repeated threat indicators associated with a domain.
7. URLs sharing suspicious infrastructure.
8. Risk history for a domain.

Use JOINs, GROUP BY, indexes and foreign-key relationships.

Do not introduce a graph database.

Also create an integration endpoint/service that accepts the fallback system's final structured output. It should update the appropriate MySQL scan/prediction/threat-indicator records.

Expected fallback result contract should support at minimum:
- scan_id
- final_classification
- risk_level or risk_score
- evidence_summary
- threat_indicators
- analysis_status
- optional reference to the MongoDB investigation document

Allowed final classifications:
- Benign
- Phishing
- Malware
- Defacement
- Unknown / Needs Review

Do not implement the fallback analysis itself; consume its output through a clean interface.

Run end-to-end tests for:
1. confident scan → MySQL
2. uncertain scan → handoff
3. fallback result returned → MySQL updated
4. domain/IP correlation query
5. scan history query
```

---

# PARI Responsibilities Summary

## Own these areas
- Existing ML baseline preservation
- Random Forest
- Logistic Regression
- Confidence threshold
- Unknown/uncertain routing
- MySQL schema
- 400 labelled URL import into MySQL
- Structured scan history
- SQL constraints and normalization
- SQL relationships and correlation
- Final structured result storage
- Integration contract for fallback results

## Do NOT own
- Webpage deep analysis implementation
- MongoDB implementation
- LLM integration implementation
- Flexible raw evidence storage
- Analyst review UI/workflow owned by Nikhil unless jointly agreed

## Integration Contract with Nikhil
Pari sends to fallback:
- scan_id
- URL
- initial ML prediction
- initial confidence
- any already-collected structured information

Nikhil returns:
- scan_id
- deep-analysis status
- final classification or Unknown/Needs Review
- risk level/score
- evidence summary
- threat indicators
- MongoDB document reference

Both developers must avoid silently changing the other's database/API contracts.
