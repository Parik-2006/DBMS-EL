# MaliciousBot 2.0 — Phase 1 Implementation Report

Status labels: **VERIFIED (tests)** = covered by automated tests run locally with mocks / isolated SQLite;
**CODE ONLY** = implemented, needs live-infrastructure verification (MySQL/Aiven, MongoDB Atlas, Render,
real websites, Playwright Chromium). No production database, deployment or external target was contacted.

## 1. Executive summary

Phase 1 hardens the existing PARI + Nikhil architecture without changing the AIML core (10 features, Random
Forest + LR exception fallback, 0.75 threshold, FinalClassifier weights, four classes). It fixes:

1. **Historical intelligence / correlation** — domains are stored and queried as public-suffix-aware registered
   domains; scans are linked to validated public IPs; domain↔IP correlation works.
2. **Database integrity** — all fallback persistence is one transaction on the *tenant* database alias,
   failures roll back and mark the scan `FAILED`, retries are idempotent, history rows link to their exact scan.
3. **MongoDB tenant isolation** — evidence is keyed by `(tenant_id, scan_id)` plus a global `investigation_id`;
   cache and screenshots are tenant-scoped; legacy documents are quarantined from normal retrieval.
4. **SSRF protection** — one outbound policy, DNS-pinned transport, per-hop redirect validation, pinned TLS
   inspection, browser egress forced through the pinned transport.
5. **Authentication / API security** — authenticated, CSRF-protected, ownership-checked APIs; a token-only worker
   API; analyst roles; validation; rate limiting; generic errors.
6. **Application hardening** — fail-closed `SECRET_KEY`, secure cookies, HTTPS/HSTS, CSP, password validation,
   secret redaction (logs + MongoDB), Gemini key moved to a header, least-privilege grants, safe migration script.

Plus related bugs: empty admin dashboard, silently dropped history rows, wrong history↔scan association,
stale timeout test, stuck scans, fake "Safe" result, unused duplicate model.

## 2. Starting point

| Item | Value |
|---|---|
| Repository | `Parik-2006/DBMS-EL` |
| Base | `origin/main` @ `bfbe4ac1fb6aa9718bd68661c1f1fe41c4405a86` (fetched; unchanged since analysis) |
| Implementation branch | `branch1` (created with `git switch -c branch1 origin/main`) |
| Untouched | `main`, `master`, `parik`, `nikhil` (no merge, no push, no force-push) |
| Local stale checkout | `main` @ `d8ec6a5` (not modified) |

## 3. The six Phase 1 improvements

### 3.1 Historical intelligence and domain/IP correlation
- **New** `User/services/domain_normalization.py`: `normalize_url()` → hostname (lower-case, IDNA/punycode,
  trailing dot stripped), registered domain, public suffix, subdomain, IP-literal detection; bundled
  public-suffix snapshot (deterministic, no network). Handles `.co.in`, `.co.uk`, `.ac.in`, IPv4/IPv6.
- `pari_domain.domain_name` = registered domain (`google.co.in`), `tld` = public suffix (`co.in`, column
  widened to 63). Applied in `views.predict` and `import_baseline_urls` (which now also has a correct
  `--database` + transaction alias).
- `HistoricalIntelligenceService` looks up `registered_domain_for(host)` (was: full hostname vs label → never
  matched). Exact-URL history unchanged. IP history uses the new `Scan.ip` link (+ legacy IP indicators) and
  reports co-hosted domains.
- `FallbackIntegrationService.link_observed_ip` records only validated **public** IPs from successful network
  analysis, updates AbuseIPDB-derived status/risk, and sets `Scan.ip`.
- `CorrelationService` rewritten: fixed the nonexistent `Scan.ip_id` reference (field now exists),
  `get_ips_by_domain`, `get_domains_by_ip`, real `get_ips_by_malicious_urls`; every query is alias-explicit.
- The PARI `root_domain` / `url_region` features intentionally still use the original label logic (model
  compatibility).

### 3.2 Database integrity and transactions
- `process_fallback_result(result, db_alias, tenant_id)` runs fallback result, 7 evidence summaries, AI evidence,
  final decision, indicators, IP link and scan completion inside `transaction.atomic(using=<tenant alias>)` with
  `select_for_update`; every ORM call uses `.using(alias)`; per-item error swallowing removed.
- On any failure: rollback, `Scan.status='FAILED'`, safe `failure_reason`; `pari_prediction` untouched.
- Idempotency: `update_or_create` everywhere; a `COMPLETED` scan returns `already_completed` and is never
  overwritten; `FAILED` scans can be retried; investigation-id mismatch rejected.
- `make_prediction` is atomic on the tenant alias and uses `get_or_create` (initial prediction never duplicated
  or overwritten); failures set `ERROR`.
- Status transitions: `UNCERTAIN → DEEP_ANALYSIS → COMPLETED | FAILED`; `CONFIDENT` for confident ML.
- New `Scan.forensic_status` (`NOT_APPLICABLE / PENDING / STORED / CACHE_ONLY / FAILED / MISSING`) records
  MongoDB durability truthfully. **MySQL and MongoDB do not share a transaction**; gaps are repaired by
  `manage.py reconcile_scans` (stale-scan recovery + forensic reconciliation, dry-run default).
- `User_maliciousbot.scan` FK links each history row to its exact scan; legacy rows keep `NULL` (never guessed).
- History view: defined `logger`, no row dropped on evidence errors, tenant-scoped Mongo lookup by the row's own
  scan, lazy stale-scan recovery.
- Router fix: related-object access follows the instance's database (`instance` hint), so `scan.url` etc. stay
  in the correct tenant DB outside request context (commands, threads).

### 3.3 MongoDB tenant isolation
- Documents carry `tenant_id` (`user:<id>`/`guest`, derived server-side), `scan_id`, `investigation_id`
  (`Scan.investigation_id`, UUID, unique), `schema_version=2`. All upserts/reads/deletes filter by tenant.
- Index definitions (`INDEX_SPECS`): unique partial `{tenant_id, scan_id}` and unique partial
  `{investigation_id}`. **Not created automatically** — `manage.py mongo_tenant_maintenance --create-indexes --apply`.
- One shared `MongoClient` per process (ping once, 60 s back-off after failure) instead of 2–4 clients per scan.
- `TenantScopedCache`: bounded LRU, lock-protected, keyed by `(tenant_id, scan_id)`, deep copies.
- Non-durable writes return `local-cache:<tenant>:<scan>` and set `forensic_status=CACHE_ONLY`.
- Documents are redacted before storage (cookies/authorization headers, API keys, secret env values).
- Screenshots: `MEDIA_ROOT/screenshots/<tenant>/<investigation-uuid>.png`; served only if the scan exists in the
  caller's own DB **and** belongs to the caller; legacy `scan_<id>_<ts>.png` names are no longer served.
- Investigation API verifies ownership and uses the tenant-scoped lookup. Tenant identity is passed explicitly into
  orchestrator worker threads.

### 3.4 SSRF protection (`User/security/outbound.py`)
- `validate_url`: http/https only; no userinfo; port allow-list (`OUTBOUND_ALLOWED_PORTS`, default 80/443/8080/8443);
  strict host parsing (bracketed IPv6 only, no zone ids, no decimal/octal/hex/short IPv4 forms, IDNA validation,
  internal hostname/suffix deny-list); DNS resolved with a timeout and **every** answer must be global
  (blocks private, loopback, link-local, multicast, reserved, unspecified, CGNAT, site-local, IPv4-mapped,
  6to4/Teredo-embedded, cloud metadata). Fails closed.
- `safe_request`: connects to the validated IP (DNS pinning → rebinding cannot redirect the connection), sends the
  original `Host`, verifies TLS against the hostname (SNI + `assert_hostname`, certifi CA), no automatic redirects
  (each `Location` re-validated, limit 3), GET/HEAD only, connect/read/overall timeouts, size cap.
- `inspect_tls`: pinned connection; `verified` is `None` when no handshake completed (port closed) — fixes the old
  "port 443 closed ⇒ untrusted SSL +1.5 Phishing" bug.
- WebpageAnalyzer / NetworkAnalyzer use it (status `BLOCKED` with `security_block` reason); target response headers
  are redacted; the process-global `socket.setdefaulttimeout` race is removed.
- VisualAnalyzer: Chromium behind a black-hole proxy (`127.0.0.1:9`, loopback bypass removed), DNS prefetch and
  background networking disabled, JS off, downloads off, service workers blocked, TLS errors **not** ignored; every
  request intercepted and fulfilled from `safe_request` (non-GET/HEAD, websockets, budget overflow aborted).
  `VISUAL_ANALYSIS_ENABLED=false` disables it. Residual risk: `--no-sandbox` on Render.
- Blocked/unavailable evidence scores nothing in FinalClassifier (verified: cannot produce Benign).

### 3.5 Authentication and API security
| Endpoint | Before | After |
|---|---|---|
| `POST /api/fallback/result/` | anonymous, csrf_exempt | **service token** (`FALLBACK_SERVICE_TOKEN` ≥32 chars, constant-time compare; disabled/503 if unset), session ignored, tenant via registry, `investigation_id` must match, 400/401/403/404/409/415 |
| `POST /api/nikhil/submit-review/` | anonymous, csrf_exempt | login + CSRF + `User.submit_review`; label/status/notes validated; updates NEEDS_REVIEW decisions to `OVERRIDDEN`; FINAL/CONFIDENT_ML require `User.override_final_decision` |
| `GET /api/nikhil/investigation/<id>/` | anonymous | login + ownership + tenant-scoped Mongo |
| `GET /api/fallback/uncertain-scans/`, `scan-status/<id>/` | anonymous | login + own scans only |
| `GET /api/correlation/*` | anonymous | login, own tenant DB |
| `/logout` | GET | POST + CSRF |
| `/status` | public details | public minimal; details for staff |
| `/health` | error text leaked | generic message |
- Roles: `manage.py setup_roles` creates **Analyst** and **Senior Analyst** groups; administrators are superusers.
- Rate limits (`User/security/ratelimit.py`, env `RATE_LIMIT_<SCOPE>=count/seconds`): login per IP and per
  username, registration, scan submission, API, review → HTTP 429 + `Retry-After`. Backend: LocMem (per process)
  or `CACHE_BACKEND=database` (shared, core DB, `createcachetable`). X-Forwarded-For is trusted only with
  `TRUSTED_PROXY_COUNT>0` (Render: 1).
- No internal exception text is returned by views or APIs.

### 3.6 Application hardening
- Settings: `SECRET_KEY` must be ≥32 chars and non-placeholder in production / DEBUG=False (else
  `ImproperlyConfigured`); secure + SameSite=Lax cookies; `SECURE_SSL_REDIRECT` (exempt `/health`); HSTS 1 day by
  default in production; nosniff; `X_FRAME_OPTIONS=DENY`; referrer/COOP policies; CSP + Permissions-Policy via
  `User.security.headers.SecurityHeadersMiddleware` (`'unsafe-inline'` kept because templates use inline
  scripts/handlers); logging through `RedactingFilter`.
- Registration: username/email validation, Django password validators, single generic duplicate message; login /
  admin-login failures use one generic message; usernames/emails no longer printed.
- Secrets: Gemini key in `x-goog-api-key` header; provider errors redacted; `.env.example` (placeholders) added and
  un-ignored; `.env` remains ignored.
- MySQL privileges: tenant DBs get `SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, DROP, REFERENCES,
  CREATE TEMPORARY TABLES, LOCK TABLES` for the app user on that schema only (no `ALL`, no `GRANT OPTION`), hosts
  from `MYSQL_APP_USER_HOSTS`, skipped when the provisioning user is the app user, failures logged. Existing
  grants are **not** revoked.
- `migrate_sqlite_to_mysql.py`: dry-run default, no import-time side effects, refuses in production, exact-name
  `--drop-database` allow-list (wildcards rejected), `--backup-confirmed --backup-path`, `--confirm MIGRATE-AND-DROP`.

## 4. Additional bugs fixed
| Bug | Fix |
|---|---|
| Admin dashboard always empty (`mb` vs `data`) | Template uses `data`; view aggregates the latest 50 rows of every active tenant read-only (no provisioning) |
| History rows silently dropped (undefined `logger`) | Logger defined; evidence errors never hide a row |
| History linked to latest scan of same URL | Exact `MaliciousBot.scan` FK |
| Stale deployment test (5000 vs 8000 ms) | Verified intentional change in `9a4a5a1`; test updated |
| Scans stuck UNCERTAIN forever | `DEEP_ANALYSIS` state, `FAILED` on errors, stale recovery (view + `reconcile_scans`) |
| Deep analysis could exceed gunicorn 30 s timeout | `NIKHIL_MAX_SECONDS` (45) enforced on collector futures, visual skipped late, AI skipped near budget; Render start command `--timeout 120 --threads 4` |
| "Safe" mock result when ML missing | Truthful 503 "ML engine unavailable", nothing persisted |
| Duplicate `User/models_review.py` (never imported) | Removed |
| Router routed related lookups to the request DB | Follows the instance's DB |

## 5. Files
**Modified:** `.gitignore`, `MaliciousBot/settings.py`, `User/api.py`, `User/db_manager.py`, `User/db_router.py`,
`User/management/commands/import_baseline_urls.py`, `User/middleware.py`, `User/models.py`, `User/screenshot_views.py`,
`User/services/{correlation_service,fallback_service,historical_intelligence_service,ml_service}.py`,
`User/services/nikhil/{gemini_provider,mongodb_repository,network_analyzer,nikhil_service,openrouter_provider,orchestration_service,trusted_domains,visual_analyzer,webpage_analyzer}.py`,
`User/test_deployment.py`, `User/views.py`, `build.sh`, `migrate_sqlite_to_mysql.py`, `render.yaml`,
`templates/{adminhome,nav,predict}.html`, `MALICIOUSBOT_MASTER_CONTEXT.md`.

**Created:** `.env.example`, `MaliciousBot/settings_test.py`, `User/security/{__init__,api,headers,outbound,ratelimit,redaction,tenancy}.py`,
`User/services/domain_normalization.py`, `User/migrations/0012_phase1_tenant_integrity.py`,
`User/migrations/0013_normalize_registered_domains.py`, `User/management/commands/{reconcile_scans,mongo_tenant_maintenance,setup_roles}.py`,
`User/tests/{__init__,helpers,test_domain_correlation,test_persistence,test_tenant_isolation,test_outbound_security,test_api_security,test_hardening}.py`,
`docs/PHASE1_IMPLEMENTATION.md`.

**Deleted:** `User/models_review.py` (unused duplicate), `User/tests.py` (empty; replaced by the `User/tests/` package).

## 6. Security architecture before → after
| Concern | Before | After |
|---|---|---|
| Outbound fetches | `requests.get/head`, raw sockets, Playwright direct; any host | Single policy, DNS-pinned, per-hop validation, browser egress via pinned transport |
| Tenant evidence key | `scan_id` (collides) | `(tenant_id, scan_id)` + `investigation_id` |
| Fallback transaction | `atomic` on core DB (no effect) | `atomic(using=tenant)` + rollback + FAILED state |
| Write APIs | anonymous + csrf_exempt | token-only worker API; session + CSRF + permission for reviews |
| Secrets | key in Gemini URL; raw errors/cookies to Mongo; PII in prints | header auth; redaction for logs and documents |
| Startup | insecure `SECRET_KEY` fallback | fail-closed in production |

## 7. Database migration requirements
- `0012_phase1_tenant_integrity` (schema): `Scan.investigation_id` (added nullable → per-row UUID backfill → unique),
  `Scan.ip` FK, `Scan.forensic_status`, `Scan.failure_reason`, `Scan.status` choice `FAILED`,
  `MaliciousBot.scan` FK, `Domain.tld` → 63 chars, AnalystReview permissions.
- `0013_normalize_registered_domains` (data, idempotent, non-destructive): recovers registered domains from each
  Domain row's URLs (rename in place / re-point on collision / split ambiguous labels); rows without URLs left
  unchanged; never deletes. Marks pre-Phase-1 fallback scans `forensic_status=PENDING`.
- Both are tenant-DB migrations (router skips the core DB). They apply to `guest_db` (`build.sh`), existing user DBs
  (on next request via `reconcile_user_database_migrations`), and new user DBs (fast bootstrap creates the final
  schema and records them applied).
- **Not executed against any live database.** Deployment commands (operator, after a backup):
  ```
  python manage.py migrate --noinput
  python manage.py migrate --database=guest_db --noinput
  python manage.py createcachetable           # if CACHE_BACKEND=database
  python manage.py setup_roles
  python manage.py reconcile_scans --all-tenants            # dry-run, then --apply
  python manage.py mongo_tenant_maintenance --create-indexes # dry-run, then --apply
  python manage.py mongo_tenant_maintenance --audit-legacy   # dry-run, then --apply
  ```
- **Backups required first:** MySQL dump of core, guest and every `maliciousbot_user_%` schema; MongoDB
  `deep_analysis_cases` export; `media/screenshots`.

## 8. Legacy evidence strategy
Unscoped MongoDB documents (no `tenant_id`) are **excluded from all normal retrieval** by the tenant filter.
`mongo_tenant_maintenance --audit-legacy` classifies each one: **VERIFIABLE** (exactly one tenant has that scan id
*and* its `pari_scan_fallback.mongo_document_reference` equals the document `_id` *and* URLs match) → backfilled
with `--apply`; **CONFLICT** (several tenants) → `quarantined=True`; **UNVERIFIABLE** → untouched. Nothing is deleted.
Because pre-Phase-1 upserts overwrote documents across tenants, some evidence may already belong to the wrong scan;
the URL check rejects those, and they stay unresolved (documented, preserved). Legacy screenshot files are not served.

## 9. Environment variables (new / changed)
`FALLBACK_SERVICE_TOKEN`, `CACHE_BACKEND`, `RATE_LIMIT_ENABLED`, `RATE_LIMIT_{LOGIN_IP,LOGIN_USER,REGISTER,SCAN,API,REVIEW}`,
`TRUSTED_PROXY_COUNT`, `OUTBOUND_ALLOWED_PORTS`, `NIKHIL_MAX_SECONDS`, `STALE_SCAN_MINUTES`, `VISUAL_ANALYSIS_ENABLED`,
`SCREENSHOT_MAX_BYTES`, `MEDIA_ROOT`, `MONGO_FALLBACK_CACHE_SIZE`, `MYSQL_APP_USER_HOSTS`, `SESSION_COOKIE_SECURE`,
`CSRF_COOKIE_SECURE`, `SECURE_SSL_REDIRECT`, `SECURE_HSTS_SECONDS`, `SECURE_HSTS_INCLUDE_SUBDOMAINS`,
`SECURE_HSTS_PRELOAD`, `SESSION_COOKIE_AGE`, `CONTENT_SECURITY_POLICY`, `LOG_LEVEL`. `SECRET_KEY` is now mandatory
(≥32 chars) in production. See `.env.example`.

## 10. Deployment prerequisites
- Render dashboard start command should match `render.yaml` (`--timeout 120`); `render.yaml` has
  `autoDeploy: false` and there are no GitHub workflows, so pushing `branch1` does not deploy by itself
  (verify the dashboard's tracked branch is `main`).
- Aiven: either `MYSQL_ADMIN_USER` with CREATE/GRANT rights, or an app user that may create `maliciousbot_user_%`
  schemas; set `MYSQL_APP_USER_HOSTS` to the user's host (often `%`).
- Set `CACHE_BACKEND=database` if more than one worker/instance runs.
- After deploy: add analysts with `manage.py setup_roles --add-analyst <username>`.

## 11. Test results (local, isolated)
| Suite | Command | Result |
|---|---|---|
| Phase 1 regression (`User/tests/`) | `python manage.py test User.tests --settings=MaliciousBot.settings_test` | **138 passed, 0 failed, 0 skipped** |
| Existing deployment suite (`User/test_deployment.py`) | default settings, outbound DNS blocked by harness | **78 passed, 0 failed**; 1 environment-excluded (`test_options_are_an_ssl_context_pyMySQL_accepts` deliberately connects to an external Aiven host) |
| `python manage.py check` | test + default settings | no issues |
| `python manage.py makemigrations --check --dry-run` | test settings | No changes detected |
| `python -m compileall MaliciousBot User` | — | OK |
| `git diff --check` | — | clean |
Environment: isolated Python 3.12 venv with the project's pinned `requirements.txt` (no global packages changed).
Coverage of the 30 requested areas: normalization, registered domains, IP correlation, historical intelligence,
rollback, alias, duplicates, exact history, Mongo isolation, index definitions, legacy handling, cache isolation,
screenshot ownership, SSRF, redirects, DNS rebinding, browser egress, authn, authz, CSRF, input validation, rate
limiting, password validation, secret redaction, header redaction, scan recovery, admin dashboard, PARI regression,
FinalClassifier regression, deployment configuration.

**Runtime-unverified (needs live infrastructure):** real MySQL/Aiven migrations and grants, MongoDB Atlas writes and
index creation, Playwright Chromium in the Render image, real TLS/DNS behaviour of `safe_request`, Gemini/OpenRouter
and TI APIs with the new code, gunicorn thread worker on Render.

## 12. Remaining limitations
- CSP keeps `'unsafe-inline'` (inline handlers in existing templates).
- LocMem rate limiting is per process unless `CACHE_BACKEND=database`.
- Chromium runs with `--no-sandbox`; disable visual analysis if renderer isolation is required.
- Deep analysis is still synchronous within the request (background workers are out of Phase 1 scope); worker
  threads that exceed the budget finish in the background (bounded by their own timeouts).
- Overwritten legacy Mongo evidence cannot be fully recovered.
- Tests `TenantTestCase` skip unless `settings_test` is used.

## 13. Rollback considerations
- Code: redeploy `bfbe4ac`. Schema: `0012`/`0013` are additive; rolling back code leaves extra nullable/defaulted
  columns, which old code ignores. `0013` has no reverse operation (data stays normalized, which old code tolerates;
  old code would create new label-style domain rows again). Restore from backup for a full revert.
- Mongo: new fields/indexes are additive; legacy documents untouched except optional backfill/quarantine flags.
- Old code expects legacy screenshot names; new screenshots use UUID names.

## 14. Final verification matrix
| Acceptance criterion | Status |
|---|---|
| Registered-domain normalization for history | VERIFIED (tests) |
| IP and domain correlation | VERIFIED (tests) |
| Tenant-alias fallback transaction | VERIFIED (tests) |
| Failed persistence never marks COMPLETED | VERIFIED (tests) |
| MongoDB evidence tenant-isolated | VERIFIED (tests, fake collection); CODE ONLY on Atlas |
| Cache tenant-isolated | VERIFIED (tests) |
| Screenshot access tenant-isolated | VERIFIED (tests) |
| Ambiguous legacy evidence handled safely | VERIFIED (tests); live audit pending |
| Outbound policy on all user-controlled paths | VERIFIED (tests, mocked DNS/transport) |
| Unsafe redirects / destinations rejected | VERIFIED (tests) |
| Browser egress isolated or disableable | VERIFIED (tests, mocked Playwright); CODE ONLY with real Chromium |
| Private APIs authenticated; write APIs CSRF/token | VERIFIED (tests) |
| Cross-user access prevented | VERIFIED (tests) |
| Analyst permissions enforced | VERIFIED (tests) |
| Login / scan / API rate limits | VERIFIED (tests) |
| Password validation | VERIFIED (tests) |
| Secret and header redaction | VERIFIED (tests) |
| Destructive script protected | VERIFIED (tests + dry-run) |
| Admin dashboard and history fixed | VERIFIED (tests) |
| AIML behaviour compatible | VERIFIED (feature vector, threshold, classifier regression) |
| Production migration / deployment | NOT PERFORMED (requires owner authorization) |
