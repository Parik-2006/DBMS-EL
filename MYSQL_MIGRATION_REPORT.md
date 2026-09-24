# MySQL Database Migration & Verification Report

**Date of Execution:** 24-September-2026 / 25-September-2026  
**Target Environment:** MySQL Community Server 8.0.44 (x86_64, Windows Service `MySQL80`)  
**Django Framework:** 5.2.11 with Python 3.12.4 (`.venv_canonical`)  
**Branch:** `nikhil`  
**Location:** `P:\DBMS EL\diploma-project`  

---

## 1. SQLite Database Backup
Before switching the application runtime to MySQL, an explicit binary backup was created:
- **Backup File Path:** `P:\DBMS EL\diploma-project\db.sqlite3.backup`
- **Backup Size:** 614,400 bytes (600 KB)
- **Backup Timestamp:** 2026-09-24 23:18:00 IST
- **Status:** Verified complete and added to `.gitignore` to prevent repository pollution. The original `db.sqlite3` remains preserved in the directory for archival purposes and is no longer accessed by any application runtime code.

---

## 2. MySQL Connection & Version
- **Driver:** `mysqlclient` 2.3.0 (C-extension) with `pymysql` 1.2.3 fallback in `MaliciousBot/__init__.py`.
- **Host:** `localhost` (127.0.0.1)
- **Port:** 3306
- **Server Version:** **8.0.44** (MySQL Community Server - GPL)
- **Charset:** `utf8mb4` with collation `utf8mb4_unicode_ci`
- **SQL Mode:** `STRICT_TRANS_TABLES`

---

## 3. Database Architecture & Registry Verification

### Control Database: `maliciousbot_core`
Contains global administrative and authentication tables, plus the dynamic user registry:
- `auth_user`
- `auth_group`
- `auth_permission`
- `auth_group_permissions`
- `auth_user_groups`
- `auth_user_user_permissions`
- `django_session`
- `django_content_type`
- `django_admin_log`
- `user_database_registry`

### Registered User Databases in `user_database_registry`:
| User ID | Username | Assigned Physical MySQL Database | Initial Status |
|---|---|---|---|
| 1 | `testuser` | `maliciousbot_user_000001` | ACTIVE |
| 2 | `testflow999` | `maliciousbot_user_000002` | ACTIVE |
| 3 | `browsertestuser01` | `maliciousbot_user_000003` | ACTIVE |
| 4 | `navuser100` | `maliciousbot_user_000004` | ACTIVE |
| 5 | `PARIK` | `maliciousbot_user_000005` | ACTIVE |
| 6 | `e2e_user` | `maliciousbot_user_000006` | ACTIVE |
| N/A | Guest / Tests | `maliciousbot_guest` | ACTIVE |

---

## 4. SQLite vs. MySQL Row Count Parity
Every individual row from SQLite was extracted, mapped according to ownership, and imported into the target MySQL schema.

| Table Name | SQLite Row Count | Total MySQL Migrated Count | Distributed Locations | Discrepancies / Mismatches |
|---|---|---|---|---|
| **Users (`auth_user`)** | 6 | 6 | `maliciousbot_core` | 0 |
| **Sessions (`django_session`)** | 47 | 47 | `maliciousbot_core` | 0 |
| **Registries (`user_database_registry`)** | 0 | 6 (provisioned) | `maliciousbot_core` | 0 |
| **Domains (`Domain`)** | 358 | 358 | User DBs + `maliciousbot_guest` | 0 |
| **URLs (`URL`)** | 425 | 425 | User DBs + `maliciousbot_guest` | 0 |
| **Scans (`Scan`)** | 74 | 74 | User DBs + `maliciousbot_guest` | 0 |
| **Predictions (`Prediction`)** | 73 | 73 | User DBs + `maliciousbot_guest` | 0 |
| **Threat Indicators (`ThreatIndicator`)** | 5 | 5 | User DBs + `maliciousbot_guest` | 0 |
| **Scan Indicators (`ScanIndicator`)** | 8 | 8 | User DBs + `maliciousbot_guest` | 0 |
| **MaliciousBot (`MaliciousBot`)** | 41 | 41 | User DBs | 0 |

**Match Rate:** **100.0%**. No data lost, no orphaned records created.

---

## 5. Schema & Foreign Key Validation
1. **InnoDB Key Constraints:**
   - `URL.url` was upgraded from unbounded `TextField` to `CharField(max_length=500, unique=True, db_index=True)` to comply with MySQL InnoDB 767/3072 byte prefix key limits.
   - `ThreatIndicator.indicator_value` was adjusted to `CharField(max_length=255)` to enable composite unique constraint `unique_together = ('indicator_type', 'indicator_value')`.
2. **Cross-Database Foreign Keys:**
   - In MySQL, foreign key constraints cannot cross schema boundaries on separate databases.
   - Fields referencing `auth_user` (`Scan.user`, `MaliciousBot.user`, `AnalystReview.user`) were updated with `db_constraint=False`.
   - Intra-database relational constraints (`URL -> Domain`, `Scan -> URL`, `Prediction -> Scan`, `ScanIndicator -> Scan`, `ScanIndicator -> ThreatIndicator`) remain fully enforced at the InnoDB level.

---

## 6. User Isolation Verification
Verified via `test_mysql_user_isolation_and_features.py`:
- User A (`test_iso_a`) and User B (`test_iso_b`) were provisioned on isolated databases (`maliciousbot_user_000015` and `maliciousbot_user_000016`).
- User A created scans `A1`, `A2`. User B created scans `B1`, `B2`.
- Direct MySQL queries verified:
  - `SELECT COUNT(*) FROM maliciousbot_user_000015.pari_scan` = 2
  - `SELECT COUNT(*) FROM maliciousbot_user_000016.pari_scan` = 2
- In User B's session, queries for User A's URLs returned 0 rows.
- Direct API access: User B requesting `/api/nikhil/investigation/<A_scan_id>/` returned `404 Not Found`.

---

## 7. Non-Destructive "Clear History" Verification
Verified across UI, API, and direct MySQL checks:
1. User A history UI showed 2 records before clearing.
2. User A clicked "CLEAR HISTORY" (sent `POST /clear-history`).
3. History page immediately rendered "No Prediction History" (0 records visible).
4. Direct MySQL inspection confirmed:
   - `SELECT COUNT(*) FROM maliciousbot_user_000015.pari_scan` = **2** (scans remained untouched).
   - `SELECT COUNT(*) FROM maliciousbot_user_000015.user_maliciousbot` = **2** (history rows remained untouched).
   - `SELECT COUNT(*) FROM maliciousbot_user_000015.history_clear_events` = **1** (reset marker created).
5. User A created a new scan `A3`.
6. History page rendered **only** `A3` (1 record visible).
7. Direct MySQL check confirmed all 3 scans (`A1`, `A2`, `A3`) physically exist.
8. Persistence check: Logged out User A and logged back in; the visibility boundary persisted.
9. Cross-user check: User B logged in and their 2 scans remained completely visible and unaffected.

---

## 8. MongoDB Atlas Consistency
- Verified live connection to cluster `Cluster0` (`nikhil_db.deep_analysis_cases`).
- Ran `verify_mongodb_atlas.py`: CRUD operations and idempotency verified.
- End-to-end integration verified via `test_e2e_fallback.py`:
  - Scan ID: `75`
  - MongoDB Document ID: `6ab52be4bb728e044147658c`
  - MySQL Status: `COMPLETED`
  - Consistency: Final classification, risk score, and timestamp match exactly between MySQL and MongoDB Atlas.

---

## 9. Comprehensive Test Suite Results
| Test Category | Script Name | Tests Run | Result | Notes |
|---|---|---|---|---|
| **Django System Check** | `manage.py check` | 1 | **PASSED** | 0 issues identified |
| **Django Migrations** | `manage.py makemigrations --check` | 1 | **PASSED** | No missing migrations |
| **MySQL Isolation & Clear History** | `test_mysql_user_isolation_and_features.py` | 6 Sections | **PASSED** | Connection, provisioning, isolation, zero deletions, API tampering |
| **Confidence Routing & Correlations** | `test_routing.py` | 7 Tests | **PASSED** | Confidence threshold 0.75, handoff contract, risk aggregation |
| **Threat Intelligence Collectors** | `test_threat_intel_complete.py` | 36 Tests | **PASSED** | AbuseIPDB, ThreatFox, URLhaus, Free-only guard |
| **Nikhil Fallback & AI Gatekeeper** | `test_nikhil_complete.py` | 62 Tests | **PASSED** | Corroboration, Gemini/OpenRouter fallback, prompt injection |
| **ML Pipeline** | `test_ml.py` | 1 Test | **PASSED** | Feature extraction, Random Forest, probabilities |
| **End-to-End Fallback Integration** | `test_e2e_fallback.py` | 1 Test | **PASSED** | Real MongoDB Atlas + SQL update |
| **Direct API Endpoints** | `test_api_direct.py` | 5 Tests | **PASSED** | Status 200 on all endpoints |
| **Playwright Browser E2E** | `test_browser_e2e.py` | 6 Tests | **PASSED** | Login, predict, confident ML, uncertain NPTEL, history UI, logout |
| **MongoDB Atlas Live Verification** | `verify_mongodb_atlas.py` | 1 Test | **PASSED** | Live Atlas CRUD |

---

## 10. Security & Secret Verification
- Environment variables (`MYSQL_HOST`, `MYSQL_PORT`, `MYSQL_USER`, `MYSQL_PASSWORD`, `MONGODB_URI`, `GEMINI_API_KEY`) are loaded strictly from `.env`.
- `.env` is confirmed in `.gitignore` and **not staged**.
- `db.sqlite3.backup` is confirmed in `.gitignore` and **not staged**.
- Zero database credentials leaked in templates, APIs, JSON responses, or browser JavaScript.
