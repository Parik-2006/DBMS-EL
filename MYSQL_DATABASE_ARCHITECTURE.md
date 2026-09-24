# MySQL Database Architecture & Multi-Tenant User Isolation

## 1. Why SQLite Was Replaced
SQLite was originally used for local proof-of-concept development, but had major structural limitations for our enterprise multi-tier architecture:
- **Concurrency & Locking:** SQLite operates with database-level file locks. Concurrent writes from multiple simultaneous users or background fallback ML workers cause database locked (`OperationalError: database is locked`) exceptions.
- **Tenant Data Isolation:** SQLite stores all application data in a single `.sqlite3` file, making per-user database isolation and visual schema separation impossible.
- **Enterprise Management & Auditing:** Production security operations centers (SOC) require client/server DBMS tools (e.g. MySQL Workbench) where individual user datastores can be inspected, backed up, or isolated independently.
- **Dynamic Routing & Scale:** Moving to MySQL 8.0+ enables horizontal scalability, isolated InnoDB storage engines per user, connection pooling, and cross-session persistence.

---

## 2. High-Level MySQL Architecture
The application runs on **MySQL 8.0+** using a **Database-Per-User Multi-Tenant Architecture** managed dynamically by Django:

```
MySQL 8.0 Server (localhost:3306)
│
├── maliciousbot_core (Control Database)
│     ├── auth_user
│     ├── auth_group
│     ├── django_session
│     ├── django_content_type
│     ├── django_admin_log
│     └── user_database_registry
│
├── maliciousbot_guest (Guest / Unauthenticated Database)
│     ├── pari_domain
│     ├── pari_url
│     ├── pari_ip
│     ├── pari_scan
│     ├── pari_prediction
│     ├── pari_threat_indicator
│     ├── pari_scan_indicator
│     ├── user_maliciousbot
│     ├── user_analystreview
│     └── history_clear_events
│
├── maliciousbot_user_000001 (User testuser)
│     ├── pari_domain
│     ├── pari_url
│     ├── pari_ip
│     ├── pari_scan
│     ├── pari_prediction
│     ├── pari_threat_indicator
│     ├── pari_scan_indicator
│     ├── user_maliciousbot
│     ├── user_analystreview
│     └── history_clear_events
│
├── maliciousbot_user_000002 (User testflow999)
│     └── [Isolated application tables]
│
└── maliciousbot_user_00000X ...
```

---

## 3. Control Database (`maliciousbot_core`)
The control database is configured as Django's `default` database alias in `settings.py`.
- **Purpose:** Manages system-wide authentication, user accounts, sessions, permissions, admin logging, and the tenant database registry.
- **Key Table — `user_database_registry`:**
  - `id`: BigInt Primary Key
  - `user_id`: Integer, indexed reference to `auth_user.id`
  - `username`: CharField(150), username snapshot
  - `database_name`: CharField(64), physical MySQL schema name (`maliciousbot_user_XXXXXX`)
  - `status`: CharField(20), status ('ACTIVE', 'SUSPENDED', etc.)
  - `created_at`: DateTimeField(auto_now_add=True)
  - `last_used_at`: DateTimeField(auto_now=True)

**Security Rules:**
- Database names are **never** derived from raw user input.
- Database names use the safe deterministic format: `maliciousbot_user_{user_id:06d}`.
- Database credentials are **never** stored in the registry or returned over APIs.

---

## 4. Per-User Database Architecture (`maliciousbot_user_XXXXXX`)
Every registered user is allocated their own isolated MySQL database.
- **Physical Isolation:** Scans, URLs, domains, and predictions created by User A are physically written to `maliciousbot_user_000001` and can never be queried or accessed from User B's connection (`maliciousbot_user_000002`).
- **Inspection in Workbench:** A security officer or evaluator can connect to MySQL Workbench and visually see each user's database as a discrete schema in the Navigator sidebar.
- **Cross-Database Foreign Keys:** Foreign keys referencing `auth_user` (e.g. `Scan.user`, `MaliciousBot.user`) are configured with `db_constraint=False` in Django ORM. This allows logical association while preserving physical multi-database boundaries on the MySQL server.

---

## 5. Table Structure in Each User Database
Each user schema contains only application tables:
1. `pari_domain`: Domain names, TLDs, reputation, aggregate risk scores.
2. `pari_url`: URLs submitted for scanning (`max_length=500, unique=True, db_index=True`).
3. `pari_ip`: Associated IP addresses, geolocation, ASN.
4. `pari_scan`: Scan event records, status (`CONFIDENT`, `UNCERTAIN`, `COMPLETED`), scan model, timestamp.
5. `pari_prediction`: Model name (`RandomForest`, `NikhilFallback`), predicted class, confidence, risk score, probability JSON.
6. `pari_threat_indicator`: Indicator type (`SHORTENER`, `DOMAIN`, `IP_ADDRESS`), indicator value (`max_length=255`), severity.
7. `pari_scan_indicator`: Many-to-many relationship mapping indicators to scans.
8. `user_maliciousbot`: History presentation table tracking prediction type, confidence string, and human-readable results.
9. `user_analystreview`: Manual analyst review decisions and feedback.
10. `history_clear_events`: Audit trail for non-destructive history visibility resets (`cleared_at` timestamp).

---

## 6. User Registration Flow
When a new user registers:
1. **Auth Creation:** User credentials are created in `auth_user` within `maliciousbot_core`.
2. **Schema Name Resolution:** `db_name = f"maliciousbot_user_{user.id:06d}"`.
3. **Database Creation:** `CREATE DATABASE IF NOT EXISTS \`db_name\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci` executed with root privileges.
4. **Django Connection Registration:** Dynamic connection configuration registered in `django.db.connections`.
5. **Schema Migration:** `call_command('migrate', database=db_alias)` automatically executes all pending migrations on the user's isolated database.
6. **Registry Tracking:** `UserDatabaseRegistry` record created in `maliciousbot_core` linking `user_id` to `db_name`.
7. **Failure Rollback:** If any step fails, the created database is dropped and the auth user rolled back, preventing orphaned accounts.

---

## 7. Dynamic Connection Management (`User/db_manager.py`)
- Connection settings are dynamically cloned from `connections.databases['default']` to maintain exact compatibility with Django 5.2 parameters (`CONN_HEALTH_CHECKS`, `OPTIONS`, `charset=utf8mb4`).
- Connections are created on demand and pooled by Django's connection handler under alias `f"user_{user.id}"`.
- Thread-local and `contextvars` management provides safe asynchronous and synchronous database context switching:
  - `set_current_db(db_alias)`
  - `get_current_db()`
  - `reset_current_db(token)`

---

## 8. Django Database Router (`User/db_router.py`)
`UserDatabaseRouter` automatically routes queries:
- **`CONTROL_APPS`** (`auth`, `sessions`, `contenttypes`, `admin`) + **`CONTROL_MODELS`** (`userdatabaseregistry`): Routed to `'default'` (`maliciousbot_core`).
- **Application Models** (`Scan`, `Prediction`, `URL`, `Domain`, `MaliciousBot`, `HistoryClearEvent`, etc.):
  - Authenticated request: Routed to the active user's connection alias (`user_{id}`).
  - Unauthenticated / guest scripts: Routed to `'guest_db'` (`maliciousbot_guest`).
- **`allow_migrate` Rule:** Restricts control tables to `'default'` and application tables to user/guest databases.

---

## 9. Migration of Existing SQLite Data (`migrate_sqlite_to_mysql.py`)
1. An explicit pre-migration backup was created: `db.sqlite3.backup` (614,400 bytes).
2. Existing SQLite rows were inspected for ownership:
   - Rows associated with active users (testuser, navuser100, PARIK, e2e_user) were migrated to their respective `maliciousbot_user_XXXXXX` databases.
   - 23 unassigned historical guest/test scans were migrated to `maliciousbot_guest`.
3. 100% row count parity was verified across all tables with 0 mismatches.

---

## 10. Non-Destructive "Clear History" Feature
- **Strict Prohibition of Deletions:** The feature performs **ZERO** SQL `DELETE` and **ZERO** MongoDB `delete_one`/`delete_many` calls.
- **Marker Design:** When the user confirms "CLEAR HISTORY", a record is inserted into `history_clear_events`:
  ```sql
  INSERT INTO history_clear_events (cleared_at, created_at) VALUES (NOW(), NOW());
  ```
- **Query Visibility Filter:** The History view (`/data`) filters records based on the most recent marker:
  ```python
  latest_clear = HistoryClearEvent.objects.using(db_alias).order_by('-cleared_at').first()
  if latest_clear:
      records = MaliciousBot.objects.using(db_alias).filter(timestamp__gt=latest_clear.cleared_at)
  else:
      records = MaliciousBot.objects.using(db_alias).all()
  ```
- **Persistent Visibility:**
  - Page refresh: Retains empty / filtered state.
  - Logout and login: Retains empty / filtered state.
  - New scans: Appear immediately after the boundary marker.
  - Physical retention: All old scans remain intact in MySQL and MongoDB Atlas for compliance and investigation.

---

## 11. Security & Isolation Model
1. **Server-Side Routing:** The routing decision is made exclusively by `request.user` server-side via `UserDatabaseMiddleware`.
2. **Client Tampering Immune:** No client-supplied parameter (`scan_id`, GET query, POST body, cookie, or header) can override the resolved database.
3. **ID Probing Prevention:** If User B attempts to access `/api/nikhil/investigation/3/` (which belongs to User A), User B's query executes against User B's database where scan 3 does not exist, immediately returning a clean `404 Not Found`.

---

## 12. MongoDB Atlas vs MySQL Responsibilities
| System | Database / Store | Responsibilities | Key Link |
|---|---|---|---|
| **MySQL (Core)** | `maliciousbot_core` | Users, authentication, sessions, permissions, database registry | `auth_user.id` |
| **MySQL (User DBs)** | `maliciousbot_user_XXXXXX` | Structured relational data: Scans, URLs, Domains, Predictions, Threat Indicators, History Events | `scan.id` |
| **MongoDB Atlas** | `deep_analysis_cases` (Collection) | Unstructured evidence documents: DOM snapshots, SSL certificates, DNS records, Visual analysis, AI Gatekeeper logs | `scan_id` (Logical Reference) |
