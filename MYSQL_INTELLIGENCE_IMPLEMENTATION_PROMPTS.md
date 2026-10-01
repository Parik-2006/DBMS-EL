# MySQL Intelligence Layer — Implementation Prompts

## Project Context

Canonical project:

```text
P:\DBMS EL\diploma-project
```

GitHub repository:

```text
https://github.com/Parik-2006/DBMS-EL.git
```

Work only on the `nikhil` branch for these changes.

**Do NOT modify the `parik` branch.**

Current architecture:

```text
PARI Random Forest
        ↓
confidence threshold
        ↓
Nikhil fallback when uncertain
        ↓
Webpage / Network / Visual / Threat Intelligence /
Prompt Injection / AI
        ↓
Evidence corroboration
        ↓
Final classification
```

Current database roles:

```text
MySQL
→ structured relational application records,
  history, indicators, user-isolated data

MongoDB
→ detailed flexible investigation case document,
  nested evidence, full AI/investigation details
```

The objective of this implementation plan is **not** to duplicate MongoDB in MySQL.

Instead:

```text
MySQL
= structured evidence + historical intelligence
  + SQL querying + analytics + context for Nikhil

MongoDB
= detailed investigation case file
```

Each prompt below is intended to be given to Kilo/agent **one at a time**. After each prompt, verify tests and database behavior before moving to the next prompt.

---

# GLOBAL RULES FOR ALL PROMPTS

These rules apply to every prompt below.

1. Work only inside:

```text
P:\DBMS EL\diploma-project
```

2. Stay on branch:

```text
nikhil
```

3. Do not checkout, modify, reset, merge, or rewrite the `parik` branch.

4. Do not delete existing working functionality.

5. Do not duplicate the entire MongoDB case document into MySQL.

6. Preserve the existing user-isolated MySQL architecture.

7. Preserve the existing MongoDB `deep_analysis_cases` structure unless a small additive change is genuinely required.

8. Use Django migrations for schema changes. Do not manually change production schema as a substitute for migrations.

9. Preserve backward compatibility for existing scans and existing database rows.

10. Do not store API keys, passwords, cookies, session tokens, authorization headers, or other secrets in MySQL.

11. Do not change the free-only AI policy:
    - `FREE_ONLY=true`
    - `ALLOW_PAID_PROVIDERS=false`
    - Gemini Free primary
    - OpenRouter Free backup
    - no paid fallback

12. Keep the existing final deterministic classifier architecture. AI remains an evidence source, not the final authority.

13. Prefer additive, normalized relational design. Avoid one giant JSON column for data that should be queryable with SQL.

14. Every schema/code change must have tests.

15. After each prompt, report:
    - files changed
    - migrations created
    - tests run
    - test results
    - any compatibility concerns
    - example SQL query demonstrating the feature

---

# PROMPT 1 — Audit the Current MySQL Data Flow

## Description

Before changing anything, inspect the existing implementation and document exactly what happens to one scan such as Scan 86.

We need a factual baseline so later changes do not duplicate existing functionality or break relationships.

## Prompt for Kilo

```text
You are working in P:\DBMS EL\diploma-project on the nikhil branch.

Do a READ-ONLY audit of the current MySQL data flow.

Do NOT modify code, database schema, migrations, git history, or the parik branch.

Trace one completed fallback scan end-to-end, preferably scan 86 if it still exists.

Identify exactly:

1. How pari_scan is created and updated.
2. How pari_url is populated.
3. How pari_prediction is populated.
4. How pari_threat_indicator is populated.
5. How pari_scan_indicator links indicators to scans.
6. How pari_domain and pari_ip are populated, if at all.
7. How analyst review/history tables are populated.
8. Where the initial RandomForest result is stored.
9. Where the final DeepAnalysis result is stored.
10. Whether the 10 PARI features are currently stored in MySQL.
11. How Local SQL historical correlation is currently calculated.
12. What structured Nikhil evidence, if any, already reaches MySQL.
13. What AI evidence, if any, already reaches MySQL.
14. Which data remains only in MongoDB.

Also inspect current Django models, migrations, serializers/views/services, and existing tests.

Produce a concise mapping:

TABLE → PURPOSE → WRITER → IMPORTANT COLUMNS → RELATIONSHIPS

Then identify duplication risks and recommend the minimum additive schema needed for the following future phases:

- PARI feature persistence
- separate initial ML record
- final decision record
- Nikhil evidence summary
- AI evidence summary
- historical domain intelligence
- indicator history/analytics

Do not implement anything yet.
```

## Expected Result

A verified baseline showing what MySQL already does and preventing unnecessary duplicate tables.

---

# PROMPT 2 — Persist the 10 PARI Features in MySQL

## Description

PARI currently extracts 10 features for Random Forest prediction. We want those values available as structured SQL data.

The 10 features are:

```text
url_len
letters_count
digits_count
special_chars_count
shortened
abnormal_url
secure_http
have_ip
url_region
root_domain
```

MongoDB should continue keeping its existing case information. MySQL should receive one structured feature record per scan.

## Scenario

A scan contains:

```text
http://192.0.2.10/login/verify
```

MySQL should make it possible to query:

```sql
SELECT *
FROM pari_scan_features
WHERE have_ip = 1
  AND secure_http = 0;
```

## Prompt for Kilo

```text
Implement Phase 1 of the MySQL intelligence layer.

Create a normalized MySQL/Django structure for the 10 PARI RandomForest input features, one feature record associated with one scan.

Required fields:

- scan_id / foreign key to pari_scan
- url_len
- letters_count
- digits_count
- special_chars_count
- shortened
- abnormal_url
- secure_http
- have_ip
- url_region
- root_domain
- created_at

Requirements:

1. Reuse the exact feature extraction logic already used by PARI.
2. Do not create a second incompatible feature extractor.
3. Preserve the existing feature order/meaning.
4. Store values in SQL-native numeric/boolean-compatible columns so they can be queried efficiently.
5. Preserve historical feature values for every scan; do not overwrite old scan features when a URL is rescanned.
6. Add a proper migration.
7. Add indexes/constraints where appropriate.
8. Make scan_id unique if the architecture guarantees one PARI feature snapshot per scan.
9. Keep MongoDB persistence intact.
10. Backward compatibility: old scans without feature rows must remain readable.
11. Add tests for creation and retrieval.
12. Add a test proving all 10 expected feature fields are persisted.
13. Add at least one SQL/query-level test for a condition such as have_ip=1 and secure_http=0.

After implementation, run Django checks and the relevant local tests.

Report the migration name, model/table name, test results, and a sample SQL query.
```

## Expected Result

MySQL becomes capable of querying the actual PARI input feature values rather than only the resulting class.

---

# PROMPT 3 — Separate Initial ML Prediction from Fallback/Final Prediction

## Description

Scan 86 exposed an important ambiguity:

```text
Stage 1:
RandomForest → Defacement → 64.81%

Stored prediction:
DeepAnalysis → Benign
```

We need MySQL to clearly distinguish:

```text
Initial ML
        vs
Fallback/Deep Analysis
        vs
Final Decision
```

## Scenario

For Scan 87:

```text
RandomForest
→ Phishing
→ 68%

Threshold
→ 75%

Confident?
→ false

Fallback
→ Nikhil
```

That entire history should be queryable.

## Prompt for Kilo

```text
Implement a clean separation between the initial PARI ML prediction and later fallback/final results in MySQL.

Do not remove or corrupt existing historical rows.

The database must explicitly represent:

INITIAL ML RESULT:
- scan
- model name
- predicted class
- confidence
- class probabilities
- confidence threshold used
- confident/uncertain flag
- created_at

FALLBACK RESULT:
- scan
- fallback model/service name
- classification if available
- confidence/risk if available
- created_at

FINAL DECISION should remain separately identifiable and will be formalized in a later prompt.

Important:

1. Reuse existing tables when practical instead of creating redundant tables.
2. Do not silently reinterpret existing DeepAnalysis rows as RandomForest rows.
3. Preserve existing application behavior.
4. Make the schema unambiguous for new scans.
5. Maintain compatibility with existing UI/history behavior.
6. Add migrations.
7. Add tests that verify a scan can have:
   RandomForest = initial result
   DeepAnalysis = fallback result
   without one overwriting the other.
8. Add a query that finds scans where initial confidence was below 0.75.
9. Add a query that finds scans where initial class differs from fallback/final class.

Do not redesign Nikhil yet. This prompt is only about clearly preserving model-stage identity in MySQL.
```

## Expected Result

MySQL can answer:

```text
What did PARI predict?
What confidence did it have?
Did it trigger Nikhil?
What did the fallback return?
```

---

# PROMPT 4 — Create a Structured Nikhil Evidence Summary in MySQL

## Description

MongoDB remains the detailed evidence store.

But MySQL should store a compact structured summary that can be queried without opening a MongoDB case document.

The evidence families are:

```text
WEBPAGE
NETWORK
VISUAL
THREAT_INTELLIGENCE
PROMPT_INJECTION
AI
SQL_HISTORY
TRUSTED_DOMAIN
```

Only persist the evidence that the current implementation actually knows how to produce. Do not invent fields.

## Scenario

Scan 86 had:

```text
Webpage       → SUCCESS
Network       → SUCCESS
Visual        → SUCCESS
Threat Intel  → SUCCESS / no malicious matches
Prompt Inject → NOT DETECTED
AI            → COMPLETED
SQL History   → no historical indicator
```

MySQL should hold a queryable summary of that state.

## Prompt for Kilo

```text
Implement a structured Nikhil evidence summary layer in MySQL.

First inspect the existing Nikhil evidence structures and use their actual terminology.

Create a normalized summary associated with each scan.

The summary should support structured fields for evidence families such as:

- webpage
- network
- visual
- threat intelligence
- prompt injection
- SQL historical evidence
- trusted-domain evidence
- AI evidence linkage/status

Do not copy raw HTML, raw screenshots, cookies, tokens, full external API payloads, or the entire MongoDB case document into MySQL.

Store compact queryable outcomes only, for example:

- status
- detected/not_detected
- match/no_match
- source count
- evidence count
- important structured flags
- reason/summary where safe and bounded
- created_at

Requirements:

1. Derive values from the existing Nikhil implementation.
2. Do not invent unsupported facts.
3. Preserve MongoDB as the full evidence case store.
4. Link every summary row to scan_id.
5. Support multiple evidence records per scan if needed.
6. Use normalized tables rather than one giant JSON field for core queryable values.
7. Add appropriate indexes.
8. Add migrations and tests.
9. Prove with a scan such as 86 that MySQL can retrieve the evidence-family summary.

Also provide SQL queries for:
- scans where threat intelligence had no match
- scans where webpage evidence was suspicious
- scans where prompt injection was detected
- scans using multiple evidence families

Do not change final classification logic yet.
```

## Expected Result

MySQL becomes a compact **structured evidence index**, while MongoDB remains the full case archive.

---

# PROMPT 5 — Store AI Evidence Summary in MySQL

## Description

Gemini is currently used as an evidence analyst when deterministic evidence is insufficient.

MongoDB can store the detailed AI analysis. MySQL should store only the structured AI summary needed for SQL queries and downstream historical analysis.

## Scenario

Gemini returns something like:

```text
provider = gemini
model = gemini-2.5-flash
status = COMPLETED
assessment = LIKELY_BENIGN
confidence = 0.82
risk_score = 0.07
```

MySQL should store these important fields.

## Prompt for Kilo

```text
Implement a structured AI evidence summary in MySQL.

Inspect the existing Gemini/Nikhil AI response schema first.

Persist only the structured fields actually available and useful for SQL querying, such as:

- scan_id
- provider
- model
- status
- assessment/classification evidence label
- confidence if returned
- risk score if returned
- gatekeeper decision / whether AI was requested
- created_at

Do NOT store:
- API keys
- authorization headers
- cookies
- raw secrets
- the entire raw prompt
- the entire raw response when a compact structured representation is sufficient

MongoDB must continue to store the detailed AI case information.

Requirements:

1. Existing free-only AI policy must remain unchanged.
2. AI remains evidence, not final authority.
3. Add migration(s).
4. Preserve old scans.
5. Add indexes useful for querying provider/model/status/assessment.
6. Add tests for AI completed, AI not-run, and AI unavailable cases where the current implementation supports them.
7. Add SQL examples:
   - count AI-completed scans
   - list low-confidence AI evidence
   - list AI assessments by model
   - compare AI assessment with final classification

Do not alter the deterministic final decision algorithm in this prompt.
```

## Expected Result

AI becomes SQL-queryable without turning MySQL into a copy of MongoDB.

---

# PROMPT 6 — Make Historical SQL Evidence Useful for Future Scans

## Description

This is the key intelligence upgrade.

Scan 86 showed:

```text
Local SQL: No historical indicator
```

Instead of MySQL only reporting that fact, future scans should be able to retrieve useful history from prior scans.

## Scenario

First scan:

```text
example.com
→ suspicious tokens
→ Benign
```

Later scan:

```text
example.com
```

MySQL can return:

```text
previous scans = 4
previous benign = 3
previous suspicious = 1
previous indicators = SUSPICIOUS_TOKENS
last seen = ...
```

That becomes evidence for Nikhil.

## Prompt for Kilo

```text
Implement historical SQL correlation as a real reusable evidence service.

When a new scan arrives, the backend should be able to query prior structured MySQL data for the target URL/domain/IP where available.

Historical context should include only evidence already stored in MySQL, such as:

- previous scan count
- first seen / last seen
- previous classifications
- previous risk scores if available
- previous PARI confidence values
- previous threat indicators
- previous analyst reviews where appropriate
- repeated suspicious indicators
- prior AI assessments if already persisted

Requirements:

1. Never treat historical data as automatically malicious.
2. Historical evidence must be a supporting evidence family.
3. Distinguish current-scan evidence from historical evidence.
4. Avoid circular self-matching: the current scan must not become its own historical evidence.
5. Query only the current user's isolated database.
6. Do not leak one user's history into another user's scan.
7. Add bounded queries so history cannot become an unreasonably large payload.
8. Return a compact normalized historical context object to Nikhil.
9. Add tests for:
   - first-seen domain
   - previously seen benign domain
   - previously suspicious domain
   - repeated indicator
   - user-isolation
10. Do not change final classification thresholds yet.

Document exactly which MySQL tables are used to produce the historical evidence.
```

## Expected Result

MySQL becomes an **evidence memory** for Nikhil.

---

# PROMPT 7 — Build Domain-Level Intelligence

## Description

The project already has a `pari_domain` table. We want it to become useful for historical analysis.

Instead of storing only a domain record, maintain structured aggregate information based on scans that have actually occurred.

## Scenario

A domain is scanned 10 times.

MySQL can provide:

```text
domain = login-example.com

first_seen       = ...
last_seen        = ...
scan_count       = 10
phishing_count   = 2
malware_count    = 0
benign_count     = 7
unknown_count    = 1
average_risk     = ...
```

These are historical aggregates, not automatic truth.

## Prompt for Kilo

```text
Enhance domain-level MySQL intelligence using the existing pari_domain structure where practical.

For each observed domain, support safely derived historical fields such as:

- first_seen
- last_seen
- total_scan_count
- counts by observed final classification
- average/aggregate risk if meaningful
- count of distinct indicators
- count of suspicious scans

Requirements:

1. Derive all aggregate values from real stored scan data.
2. Do not hard-code or manually invent counts.
3. Define how aggregates are updated when a scan completes.
4. Ensure rescans do not double-count the same event.
5. Preserve user isolation.
6. Keep domain identity normalized.
7. Add indexes for domain lookup.
8. Add tests covering first scan, repeated scan, different classifications, and rescans.
9. Provide SQL examples for:
   - frequently scanned domains
   - domains with repeated suspicious indicators
   - domains with mixed historical classifications

Do not turn aggregate history into an automatic malicious verdict.
```

## Expected Result

A domain becomes a useful **historical entity** instead of just a passive lookup row.

---

# PROMPT 8 — Strengthen Threat Indicator History and Relationships

## Description

Scan 86 already demonstrates a good relational pattern:

```text
pari_threat_indicator
        ↓
pari_scan_indicator
        ↓
pari_scan
```

We should use that relationship for real historical queries.

## Scenario

Across many scans:

```text
SUSPICIOUS_TOKENS
→ seen 13 times
→ associated with 8 URLs
→ associated with 4 domains
```

MySQL should be able to answer this.

## Prompt for Kilo

```text
Audit and improve the existing threat-indicator relational design.

Preserve:

pari_threat_indicator
    indicator definition
        ↓
pari_scan_indicator
    association
        ↓
pari_scan
    scan event

Ensure the schema can support historical queries such as:

- how often an indicator was observed
- which scans contain an indicator
- which URLs/domains repeatedly produce an indicator
- indicator severity distribution
- indicators seen together in the same scan

Requirements:

1. Reuse the existing tables where possible.
2. Avoid creating duplicate indicator tables.
3. Add unique/index constraints where logically correct.
4. Preserve historical indicator events.
5. Do not merge different indicators just because their names are similar.
6. Add tests for scan-indicator linking.
7. Add SQL demonstration queries for:
   - most frequently observed indicators
   - indicators repeated on the same domain
   - scans containing multiple indicators
   - medium/high severity indicator occurrences

Keep the distinction between:
- indicator definition
- indicator-to-scan association
- final classification
```

## Expected Result

Threat indicators become a real SQL-queryable **historical evidence graph**.

---

# PROMPT 9 — Add Evidence Reasons / Explainability Metadata

## Description

The current MySQL indicator row tells us:

```text
URL
SUSPICIOUS_TOKENS
MEDIUM
```

But for investigation we also want to know where that evidence came from and why it was recorded.

## Scenario

Instead of only:

```text
SUSPICIOUS_TOKENS
```

we want something conceptually like:

```text
family = URL
source = PARI
reason = suspicious login/verification token pattern
severity = MEDIUM
```

This does not mean the evidence is automatically malicious.

## Prompt for Kilo

```text
Add structured explainability metadata to evidence records, using only information actually available from the current analysis pipeline.

For each structured evidence item, support fields such as:

- scan_id
- evidence_family
- source_component
- evidence_type
- indicator/value
- severity where already defined
- reason/summary
- created_at

Requirements:

1. Do not store raw sensitive content.
2. Do not invent explanations that the detector did not produce.
3. Keep reason text bounded and suitable for SQL storage.
4. Maintain compatibility with existing indicator records.
5. Preserve MongoDB as the detailed evidence store.
6. Make evidence provenance explicit:
   e.g. PARI, Network, ThreatFox, URLhaus, SQL History, Gemini.
7. Add tests confirming evidence provenance is retained.
8. Provide a SQL query that explains all evidence recorded for a given scan_id.

The objective is to make a scan explainable from structured MySQL records.
```

## Expected Result

For a scan, MySQL can answer:

> **What evidence was observed, which subsystem produced it, and what was its structured reason?**

---

# PROMPT 10 — Create a Clean Final Decision Record

## Description

The final classification should be clearly separated from intermediate predictions and evidence.

For Scan 86:

```text
Initial ML:
Defacement / 64.81%

Nikhil:
Fallback

AI:
LIKELY_BENIGN

Corroboration:
3 families

Final:
Benign

Risk:
0.07
```

That should be represented as a clean final decision record.

## Prompt for Kilo

```text
Create a structured final decision record in MySQL.

The final decision record must be clearly separate from:

- initial RandomForest prediction
- individual evidence records
- AI evidence
- historical SQL context

Store fields appropriate to the actual implementation, such as:

- scan_id
- final_classification
- final_risk_score
- decision_status
- decision method/source
- corroboration strength
- number of evidence families
- decision timestamp

Do not invent scores or evidence.

Requirements:

1. One final decision per completed scan unless the current architecture explicitly supports revisions.
2. Preserve Unknown / Needs Review when the system produces it.
3. Preserve analyst review separately.
4. Do not overwrite initial ML results.
5. Add indexes for classification/risk/time queries.
6. Add tests proving initial and final results remain distinguishable.
7. Provide SQL queries for:
   - all final Benign scans
   - all Unknown/Needs Review scans
   - high-risk scans
   - scans where initial ML and final classification differ
   - scans with strong corroboration

Keep the final deterministic classifier unchanged in this prompt; only make its result cleanly persistable and queryable.
```

## Expected Result

MySQL becomes the structured **official decision record** for each scan.

---

# PROMPT 11 — Feed MySQL Historical Evidence Back into Nikhil

## Description

This connects everything.

MySQL is no longer only a database that receives data. It becomes an evidence provider.

## Scenario

User scans:

```text
example.com/login
```

MySQL finds:

```text
previous scans = 5
previous suspicious scans = 2
SUSPICIOUS_TOKENS previously observed = 3
last risk = 0.21
```

Nikhil receives this as one evidence family:

```text
SQL_HISTORY
```

Then it combines that with current:

```text
WEBPAGE
NETWORK
VISUAL
THREAT_INTELLIGENCE
AI
```

## Prompt for Kilo

```text
Connect the historical MySQL evidence service to the Nikhil evidence pipeline.

For each new uncertain scan:

1. Extract current URL/domain/IP identifiers as currently supported.
2. Query only the current user's MySQL database.
3. Retrieve bounded historical context.
4. Normalize that context into the existing Nikhil evidence format.
5. Treat it as an independent evidence family named consistently with the existing architecture, such as SQL_HISTORY if that is the current terminology.
6. Include historical evidence only when real historical records exist.
7. Do not fabricate a negative/positive history result.
8. Prevent the current scan from matching itself.
9. Do not send unnecessary raw SQL data to Gemini.
10. Include only compact structured historical evidence in the AI evidence payload when AI is actually requested.
11. Preserve MongoDB full case storage.

The resulting pipeline should conceptually be:

PARI
→ Nikhil
→ current evidence collectors
+
MySQL historical evidence
→ evidence normalization
→ AI when gatekeeper requires it
→ corroboration
→ final decision

Add tests proving:
- first-seen target produces no false historical evidence
- repeated target retrieves prior history
- historical indicator is included correctly
- one user's history cannot appear in another user's scan
- AI payload contains bounded normalized SQL history when appropriate

Do not change the AI provider policy or final classification policy in this prompt.
```

## Expected Result

MySQL becomes an active **historical evidence source** for Nikhil.

---

# PROMPT 12 — Add DBMS Intelligence Queries / Reporting

## Description

Once all previous layers work, create SQL queries that demonstrate the actual DBMS value of the project.

This is useful for both the application and DBMS EL demonstration.

## Required query categories

```text
1. uncertain ML scans
2. initial vs final disagreement
3. scans that required AI
4. frequently scanned domains
5. repeated suspicious indicators
6. high-risk historical scans
7. scans with multiple evidence families
8. domains with mixed historical classifications
9. suspicious feature combinations
10. AI assessment vs final classification
```

## Prompt for Kilo

```text
Create a read-only SQL reporting/query layer for the MySQL intelligence database.

Do not change classification behavior.

Create documented SQL queries for:

1. Scans where RandomForest confidence < 0.75.
2. Scans where initial ML class differs from final class.
3. Scans that required Nikhil fallback.
4. Scans where AI was requested/completed.
5. Most frequently scanned domains.
6. Indicators observed most frequently.
7. Indicators repeated on the same domain.
8. High-risk scans.
9. Scans with multiple independent evidence families.
10. Domains with mixed historical outcomes.
11. Scans where have_ip=1 and secure_http=0.
12. Scans containing suspicious URL indicators but no threat-intelligence match.
13. AI evidence compared with final classification.
14. Historical SQL evidence retrieved for a target.

Prefer joins over application-side loops where appropriate.

Use parameterized queries where these are called from application code.

Add documentation under the existing docs structure, preferably extending docs/DATABASE.md or creating a clearly named SQL intelligence document.

Do not store secrets or raw external API payloads.
```

## Expected Result

The DBMS component can demonstrate real relational querying, joins, aggregation, filtering, history, and evidence analysis.

---

# PROMPT 13 — Optimize Relationships, Constraints, and Indexes

## Description

After functionality is complete, improve relational integrity and query performance without changing behavior.

## Prompt for Kilo

```text
Perform a final database design review of the newly implemented MySQL intelligence layer.

Focus on:

- foreign keys
- one-to-one vs one-to-many relationships
- uniqueness constraints
- indexes
- nullable fields
- timestamp consistency
- user isolation
- cascade behavior
- historical record preservation

Review at minimum:

pari_scan
pari_url
pari_scan_features (or the actual implemented feature table)
pari_prediction / initial prediction structure
pari_threat_indicator
pari_scan_indicator
pari_domain
pari_ip
Nikhil evidence summary structures
AI summary structure
final decision structure
history_clear_events
user_maliciousbot

Do not redesign unnecessarily.

For every recommended change:
- explain the reason
- verify existing data compatibility
- create migrations
- add/adjust tests

Pay particular attention to preventing:
- duplicate feature rows for one scan
- orphaned scan indicators
- cross-user data access
- accidental deletion of historical intelligence
```

## Expected Result

The schema becomes safer and cleaner after the intelligence features are working.

---

# PROMPT 14 — Full Fresh-Scan Verification

## Description

Do a complete real-world verification after all implementation phases.

The test should resemble the Scan 86 experiment but verify both databases together.

Use a safe synthetic test URL.

## Prompt for Kilo

```text
Run a full end-to-end verification of the MySQL intelligence layer on a fresh scan.

Use a safe synthetic/documentation URL suitable for local testing; do not interact with a real malicious site.

Capture one complete scan from:

1. URL submission
2. PARI feature extraction
3. RandomForest prediction
4. confidence threshold decision
5. Nikhil routing if uncertain
6. Webpage evidence
7. Network evidence
8. Visual evidence
9. Threat intelligence evidence
10. Prompt injection result
11. SQL historical evidence
12. AI gatekeeper
13. Gemini evidence if requested
14. evidence corroboration
15. final classification
16. MySQL persistence
17. MongoDB persistence

Then verify in MySQL:

- pari_scan
- URL record
- initial ML record
- PARI feature record
- threat indicator records
- scan-indicator links
- Nikhil evidence summary
- AI summary when applicable
- final decision

Verify in MongoDB:

- same logical scan_id
- full investigation case
- detailed evidence
- AI details if AI ran

Finally produce a one-screen mapping:

SCAN ID
→ MySQL records created
→ MongoDB case created
→ evidence families
→ AI status
→ final classification

Also run the complete relevant local test suite.

Do not modify production logic during this verification unless a clearly documented defect is discovered.
```

## Expected Result

One fresh scan proves the entire MySQL + MongoDB architecture works together.

---

# PROMPT 15 — Final Documentation Update

## Description

Document the finished architecture so another developer can understand why both databases exist.

## Prompt for Kilo

```text
Update the project documentation to explain the final MySQL + MongoDB architecture.

At minimum document:

1. Why MySQL is used.
2. Why MongoDB is used.
3. What data belongs in MySQL.
4. What data belongs in MongoDB.
5. How MySQL historical evidence is used by Nikhil.
6. How AI evidence is summarized in MySQL while detailed AI case data remains in MongoDB.
7. How PARI 10 features are persisted and queried.
8. How initial ML differs from fallback/final classification.
9. How threat indicators are related to scans.
10. How domain history is represented.
11. How users remain isolated.
12. Example SQL queries showing the intelligence role of MySQL.
13. One end-to-end Scan 86-style example showing:
       initial ML
       → evidence
       → historical SQL
       → AI
       → corroboration
       → final decision

Keep terminology consistent with the actual implementation.

Do not claim capabilities that are not implemented.

Update the existing docs rather than creating unnecessary duplicate documentation.
```

---

# Final Target Architecture

After all phases are complete, the intended architecture should look like:

```text
                         USER URL
                            │
                            ▼
                     PARI / RANDOM FOREST
                            │
                 ┌──────────┴──────────┐
                 │                     │
          10 PARI FEATURES       INITIAL ML RESULT
                 │                     │
                 └──────────┬──────────┘
                            ▼
                          MySQL
                 Structured current data
                            │
                 historical SQL context
                            │
                            ▼
                         NIKHIL
                            │
      ┌─────────────┬───────┼────────┬──────────────┐
      ▼             ▼       ▼        ▼              ▼
   WEBPAGE       NETWORK  VISUAL   THREAT       PROMPT
                                    INTEL        INJECTION
      │             │       │        │              │
      └─────────────┴───────┴────────┴──────────────┘
                            │
                            ▼
                         MongoDB
                  Full detailed case
                            │
                            ▼
                    Evidence Normalizer
                            │
                 MySQL historical context
                            │
                            ▼
                        AI Gatekeeper
                            │
                  AI required when needed
                            │
                            ▼
                     Gemini 2.5 Flash
                            │
                            ▼
                       AI Evidence
                            │
                            ▼
                    Evidence Corroboration
                            │
                            ▼
                  Deterministic Final Decision
                       ┌─────────────┐
                       │             │
                       ▼             ▼
                    MySQL        MongoDB
              Structured record  Full case
```

## Simple Role of Each Database

```text
MYSQL
─────
"What structured things do we know?"
"What happened before?"
"How many times?"
"Which scans?"
"Which indicators?"
"What features?"
"What did the models say?"
"What final decisions occurred?"
"What historical context can Nikhil use?"

MONGODB
────────
"Show me the complete investigation case."
"Give me the detailed nested evidence."
"Show the full AI/evidence document."
"Show the complete case associated with this scan."
```

## Important Design Principle

Do not aim for:

```text
MySQL = copy of MongoDB
```

Aim for:

```text
MySQL = structured intelligence + history + SQL analysis

MongoDB = detailed investigation evidence
```

The two databases should **work together**, not compete with each other.
