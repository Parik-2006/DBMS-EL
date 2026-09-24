import os
import sys
import sqlite3
import MySQLdb
import django

# Setup environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'MaliciousBot.settings')
django.setup()

from django.conf import settings
from django.core.management import call_command
from django.utils import timezone
from User.db_manager import (
    ensure_mysql_database_exists,
    register_database_connection,
    get_user_db_name,
    get_mysql_server_config,
)
from User.models import UserDatabaseRegistry

def run_migration():
    print("=" * 70)
    print("DJANGO SQLITE -> MYSQL MULTI-DATABASE MIGRATION")
    print("=" * 70)

    sqlite_path = os.path.join(settings.BASE_DIR, 'db.sqlite3')
    backup_path = os.path.join(settings.BASE_DIR, 'db.sqlite3.backup')
    print(f"SQLite DB: {sqlite_path} ({os.path.getsize(sqlite_path)} bytes)")
    print(f"SQLite Backup: {backup_path} ({os.path.getsize(backup_path)} bytes)")

    # 1. Inspect SQLite Counts
    s_conn = sqlite3.connect(sqlite_path)
    s_conn.row_factory = sqlite3.Row
    s_cur = s_conn.cursor()

    sqlite_counts = {}
    tables = [
        'auth_user', 'django_session', 'pari_domain', 'pari_url', 'pari_ip',
        'pari_scan', 'pari_prediction', 'pari_threat_indicator',
        'pari_scan_indicator', 'pari_analyst_review', 'User_maliciousbot'
    ]
    for tbl in tables:
        try:
            s_cur.execute(f'SELECT COUNT(*) FROM "{tbl}"')
            sqlite_counts[tbl] = s_cur.fetchone()[0]
        except Exception as e:
            sqlite_counts[tbl] = 0
        print(f"  SQLite {tbl:<25}: {sqlite_counts[tbl]} rows")

    # 2. Setup MySQL Control Database (maliciousbot_core) and Guest Database
    print("\nStep 2: Initializing MySQL databases...")
    cfg = get_mysql_server_config()
    core_db = os.environ.get('MYSQL_CORE_DATABASE', 'maliciousbot_core')
    guest_db = 'maliciousbot_guest'

    # Reset any partial previous databases
    conn_raw = MySQLdb.connect(host=cfg['HOST'], port=cfg['PORT'], user=cfg['USER'], passwd=cfg['PASSWORD'])
    cur_raw = conn_raw.cursor()
    cur_raw.execute("SHOW DATABASES LIKE 'maliciousbot_%'")
    for (dname,) in cur_raw.fetchall():
        cur_raw.execute(f"DROP DATABASE `{dname}`")
    conn_raw.commit()
    conn_raw.close()

    ensure_mysql_database_exists(core_db)
    ensure_mysql_database_exists(guest_db)
    register_database_connection('guest_db', guest_db)


    print("  Applying migrations to maliciousbot_core (default)...")
    call_command('migrate', database='default', interactive=False, verbosity=1)

    print("  Applying migrations to maliciousbot_guest (guest_db)...")
    call_command('migrate', database='guest_db', interactive=False, verbosity=1)

    # 3. Migrate auth_user and django_session to maliciousbot_core
    print("\nStep 3: Migrating auth_user and sessions into maliciousbot_core...")
    m_conn_core = MySQLdb.connect(
        host=cfg['HOST'], port=cfg['PORT'], user=cfg['USER'], passwd=cfg['PASSWORD'], db=core_db
    )
    m_cur_core = m_conn_core.cursor()

    s_cur.execute("SELECT * FROM auth_user")
    auth_users = s_cur.fetchall()
    for u in auth_users:
        m_cur_core.execute("""
            INSERT INTO auth_user (id, password, last_login, is_superuser, username,
                                   first_name, last_name, email, is_staff, is_active, date_joined)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE username=VALUES(username)
        """, (
            u['id'], u['password'], u['last_login'], u['is_superuser'], u['username'],
            u['first_name'], u['last_name'], u['email'], u['is_staff'], u['is_active'], u['date_joined']
        ))
    m_conn_core.commit()

    # Update auto_increment for auth_user
    m_cur_core.execute("SELECT MAX(id) FROM auth_user")
    max_uid = m_cur_core.fetchone()[0] or 0
    m_cur_core.execute(f"ALTER TABLE auth_user AUTO_INCREMENT = {max_uid + 1}")
    m_conn_core.commit()
    print(f"  Migrated {len(auth_users)} users to {core_db}.auth_user.")

    # Sessions
    s_cur.execute("SELECT * FROM django_session")
    sessions = s_cur.fetchall()
    for s in sessions:
        m_cur_core.execute("""
            INSERT INTO django_session (session_key, session_data, expire_date)
            VALUES (%s, %s, %s)
            ON DUPLICATE KEY UPDATE expire_date=VALUES(expire_date)
        """, (s['session_key'], s['session_data'], s['expire_date']))
    m_conn_core.commit()
    print(f"  Migrated {len(sessions)} sessions to {core_db}.django_session.")

    # 4. Provision per-user databases and registries
    print("\nStep 4: Provisioning isolated databases for each registered user...")
    user_db_map = {}
    for u in auth_users:
        uid = u['id']
        uname = u['username']
        udb_name = get_user_db_name(uid)
        udb_alias = f"user_{uid}"
        user_db_map[uid] = {'name': udb_name, 'alias': udb_alias, 'username': uname}

        ensure_mysql_database_exists(udb_name)
        register_database_connection(udb_alias, udb_name)

        # Run user table migrations on the user database
        call_command('migrate', database=udb_alias, interactive=False, verbosity=0)

        # Register in user_database_registry in maliciousbot_core
        reg, _ = UserDatabaseRegistry.objects.using('default').update_or_create(
            user_id=uid,
            defaults={
                'username': uname,
                'database_name': udb_name,
                'status': 'active',
                'last_used_at': timezone.now()
            }
        )
        print(f"  User {uid} ({uname}) -> Database: {udb_name} [Ready]")

    # Helper function to insert records into a target MySQL database
    def get_mysql_conn(dbname):
        return MySQLdb.connect(
            host=cfg['HOST'], port=cfg['PORT'], user=cfg['USER'], passwd=cfg['PASSWORD'],
            db=dbname, charset='utf8mb4'
        )

    # 5. Migrate user-specific application data into each user's database
    print("\nStep 5: Migrating isolated application data into per-user databases...")
    for uid, uinfo in user_db_map.items():
        udb = uinfo['name']
        u_conn = get_mysql_conn(udb)
        u_cur = u_conn.cursor()

        # Scans for this user
        s_cur.execute("SELECT * FROM pari_scan WHERE user_id = ?", (uid,))
        user_scans = s_cur.fetchall()
        scan_ids = [s['id'] for s in user_scans]

        if not scan_ids:
            # Check if there are MaliciousBot rows
            s_cur.execute("SELECT * FROM User_maliciousbot WHERE user_id = ?", (uid,))
            mb_rows = s_cur.fetchall()
            for mb in mb_rows:
                u_cur.execute("""
                    INSERT INTO User_maliciousbot (id, url, bot, prediction, prediction_type, confidence, timestamp, user_id)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE url=VALUES(url)
                """, (mb['id'], mb['url'], mb['bot'], mb['prediction'], mb['prediction_type'], mb['confidence'], mb['timestamp'], mb['user_id']))
            u_conn.commit()
            print(f"  User {uid} ({uinfo['username']}): 0 scans, {len(mb_rows)} MaliciousBot rows imported.")
            u_conn.close()
            continue

        # Get referenced URLs
        url_ids = list(set([s['url_id'] for s in user_scans]))
        placeholders = ','.join(['?'] * len(url_ids))
        s_cur.execute(f"SELECT * FROM pari_url WHERE id IN ({placeholders})", url_ids)
        user_urls = s_cur.fetchall()

        # Get referenced Domains
        domain_ids = list(set([u['domain_id'] for u in user_urls if u['domain_id'] is not None]))
        if domain_ids:
            d_placeholders = ','.join(['?'] * len(domain_ids))
            s_cur.execute(f"SELECT * FROM pari_domain WHERE id IN ({d_placeholders})", domain_ids)
            user_domains = s_cur.fetchall()
        else:
            user_domains = []

        # Predictions
        s_placeholders = ','.join(['?'] * len(scan_ids))
        s_cur.execute(f"SELECT * FROM pari_prediction WHERE scan_id IN ({s_placeholders})", scan_ids)
        user_predictions = s_cur.fetchall()

        # Scan Indicators
        s_cur.execute(f"SELECT * FROM pari_scan_indicator WHERE scan_id IN ({s_placeholders})", scan_ids)
        user_scan_indicators = s_cur.fetchall()

        # Threat Indicators
        ti_ids = list(set([si['indicator_id'] for si in user_scan_indicators]))
        if ti_ids:
            ti_placeholders = ','.join(['?'] * len(ti_ids))
            s_cur.execute(f"SELECT * FROM pari_threat_indicator WHERE id IN ({ti_placeholders})", ti_ids)
            user_tis = s_cur.fetchall()
        else:
            user_tis = []

        # MaliciousBot rows
        s_cur.execute("SELECT * FROM User_maliciousbot WHERE user_id = ?", (uid,))
        mb_rows = s_cur.fetchall()

        # Insert Domains
        for d in user_domains:
            u_cur.execute("""
                INSERT INTO pari_domain (id, domain_name, tld, status, risk_score, last_scanned, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE domain_name=VALUES(domain_name)
            """, (d['id'], d['domain_name'], d['tld'], d['status'], d['risk_score'], d['last_scanned'], d['created_at'], d['updated_at']))

        # Insert URLs
        for url in user_urls:
            u_cur.execute("""
                INSERT INTO pari_url (id, url, source, baseline_label, created_at, domain_id)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE url=VALUES(url)
            """, (url['id'], url['url'][:500], url['source'], url['baseline_label'], url['created_at'], url['domain_id']))

        # Insert Threat Indicators
        for ti in user_tis:
            u_cur.execute("""
                INSERT INTO pari_threat_indicator (id, indicator_type, indicator_value, severity, created_at)
                VALUES (%s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE indicator_type=VALUES(indicator_type)
            """, (ti['id'], ti['indicator_type'], ti['indicator_value'][:255], ti['severity'], ti['created_at']))

        # Insert Scans
        for s in user_scans:
            u_cur.execute("""
                INSERT INTO pari_scan (id, status, initial_model, fallback_model, created_at, updated_at, completed_at, url_id, user_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE status=VALUES(status)
            """, (s['id'], s['status'], s['initial_model'], s['fallback_model'], s['created_at'], s['updated_at'], s['completed_at'], s['url_id'], s['user_id']))

        # Insert Predictions
        for p in user_predictions:
            u_cur.execute("""
                INSERT INTO pari_prediction (id, model_name, predicted_class, confidence, risk_score, probabilities, created_at, updated_at, scan_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE model_name=VALUES(model_name)
            """, (p['id'], p['model_name'], p['predicted_class'], p['confidence'], p['risk_score'], p['probabilities'], p['created_at'], p['updated_at'], p['scan_id']))

        # Insert Scan Indicators
        for si in user_scan_indicators:
            u_cur.execute("""
                INSERT INTO pari_scan_indicator (id, detected_at, indicator_id, scan_id)
                VALUES (%s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE detected_at=VALUES(detected_at)
            """, (si['id'], si['detected_at'], si['indicator_id'], si['scan_id']))

        # Insert MaliciousBot rows
        for mb in mb_rows:
            u_cur.execute("""
                INSERT INTO User_maliciousbot (id, url, bot, prediction, prediction_type, confidence, timestamp, user_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE url=VALUES(url)
            """, (mb['id'], mb['url'], mb['bot'], mb['prediction'], mb['prediction_type'], mb['confidence'], mb['timestamp'], mb['user_id']))

        # Update AUTO_INCREMENT sequences
        for tname in ['pari_domain', 'pari_url', 'pari_threat_indicator', 'pari_scan', 'pari_prediction', 'pari_scan_indicator', 'User_maliciousbot']:
            u_cur.execute(f"SELECT COALESCE(MAX(id), 0) FROM `{tname}`")
            m_id = u_cur.fetchone()[0]
            if m_id > 0:
                u_cur.execute(f"ALTER TABLE `{tname}` AUTO_INCREMENT = {m_id + 1}")

        u_conn.commit()
        u_conn.close()
        print(f"  User {uid} ({uinfo['username']}) -> {udb}: {len(user_scans)} scans, {len(user_predictions)} preds, {len(user_urls)} urls, {len(user_domains)} domains, {len(mb_rows)} bot rows.")

    # 6. Migrate Guest Scans & Baseline Dataset into maliciousbot_guest
    print("\nStep 6: Migrating unassigned guest scans and baseline dataset into maliciousbot_guest...")
    g_conn = get_mysql_conn(guest_db)
    g_cur = g_conn.cursor()

    # 6a. All domains into guest_db
    s_cur.execute("SELECT * FROM pari_domain")
    all_domains = s_cur.fetchall()
    for d in all_domains:
        g_cur.execute("""
            INSERT INTO pari_domain (id, domain_name, tld, status, risk_score, last_scanned, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE domain_name=VALUES(domain_name)
        """, (d['id'], d['domain_name'], d['tld'], d['status'], d['risk_score'], d['last_scanned'], d['created_at'], d['updated_at']))

    # 6b. All baseline URLs + guest scan URLs into guest_db
    s_cur.execute("SELECT * FROM pari_url")
    all_urls = s_cur.fetchall()
    for url in all_urls:
        g_cur.execute("""
            INSERT INTO pari_url (id, url, source, baseline_label, created_at, domain_id)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE url=VALUES(url)
        """, (url['id'], url['url'][:500], url['source'], url['baseline_label'], url['created_at'], url['domain_id']))

    # 6c. All threat indicators into guest_db
    s_cur.execute("SELECT * FROM pari_threat_indicator")
    all_tis = s_cur.fetchall()
    for ti in all_tis:
        g_cur.execute("""
            INSERT INTO pari_threat_indicator (id, indicator_type, indicator_value, severity, created_at)
            VALUES (%s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE indicator_type=VALUES(indicator_type)
        """, (ti['id'], ti['indicator_type'], ti['indicator_value'][:255], ti['severity'], ti['created_at']))

    # 6d. Unassigned guest scans (user_id IS NULL)
    s_cur.execute("SELECT * FROM pari_scan WHERE user_id IS NULL")
    guest_scans = s_cur.fetchall()
    guest_scan_ids = [s['id'] for s in guest_scans]

    for s in guest_scans:
        g_cur.execute("""
            INSERT INTO pari_scan (id, status, initial_model, fallback_model, created_at, updated_at, completed_at, url_id, user_id)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE status=VALUES(status)
        """, (s['id'], s['status'], s['initial_model'], s['fallback_model'], s['created_at'], s['updated_at'], s['completed_at'], s['url_id'], None))

    # 6e. Predictions for guest scans
    if guest_scan_ids:
        gs_placeholders = ','.join(['?'] * len(guest_scan_ids))
        s_cur.execute(f"SELECT * FROM pari_prediction WHERE scan_id IN ({gs_placeholders})", guest_scan_ids)
        guest_predictions = s_cur.fetchall()
        for p in guest_predictions:
            g_cur.execute("""
                INSERT INTO pari_prediction (id, model_name, predicted_class, confidence, risk_score, probabilities, created_at, updated_at, scan_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE model_name=VALUES(model_name)
            """, (p['id'], p['model_name'], p['predicted_class'], p['confidence'], p['risk_score'], p['probabilities'], p['created_at'], p['updated_at'], p['scan_id']))

        # 6f. Scan indicators for guest scans
        s_cur.execute(f"SELECT * FROM pari_scan_indicator WHERE scan_id IN ({gs_placeholders})", guest_scan_ids)
        guest_sis = s_cur.fetchall()
        for si in guest_sis:
            g_cur.execute("""
                INSERT INTO pari_scan_indicator (id, detected_at, indicator_id, scan_id)
                VALUES (%s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE detected_at=VALUES(detected_at)
            """, (si['id'], si['detected_at'], si['indicator_id'], si['scan_id']))
    else:
        guest_predictions = []
        guest_sis = []

    # Update auto_increment in guest_db
    for tname in ['pari_domain', 'pari_url', 'pari_threat_indicator', 'pari_scan', 'pari_prediction', 'pari_scan_indicator']:
        g_cur.execute(f"SELECT COALESCE(MAX(id), 0) FROM `{tname}`")
        m_id = g_cur.fetchone()[0]
        if m_id > 0:
            g_cur.execute(f"ALTER TABLE `{tname}` AUTO_INCREMENT = {m_id + 1}")

    g_conn.commit()
    g_conn.close()
    print(f"  Guest DB: {len(all_domains)} domains, {len(all_urls)} URLs, {len(all_tis)} threat indicators, {len(guest_scans)} guest scans, {len(guest_predictions)} guest predictions, {len(guest_sis)} scan indicators.")

    # 7. Verification and Row Count Summary
    print("\n" + "=" * 70)
    print("MIGRATION VERIFICATION & RECONCILIATION")
    print("=" * 70)

    # Count users across MySQL
    m_cur_core.execute("SELECT COUNT(*) FROM auth_user")
    my_user_count = m_cur_core.fetchone()[0]
    m_cur_core.execute("SELECT COUNT(*) FROM django_session")
    my_session_count = m_cur_core.fetchone()[0]
    m_cur_core.execute("SELECT COUNT(*) FROM user_database_registry")
    my_registry_count = m_cur_core.fetchone()[0]

    print(f"auth_user (Core DB)             : SQLite={sqlite_counts['auth_user']}, MySQL={my_user_count} -> MATCH: {sqlite_counts['auth_user'] == my_user_count}")
    print(f"django_session (Core DB)        : SQLite={sqlite_counts['django_session']}, MySQL={my_session_count} -> MATCH: {sqlite_counts['django_session'] == my_session_count}")
    print(f"user_database_registry (Core DB): Registries={my_registry_count}")

    # Aggregate counts across all user databases + guest database
    total_my_scans = 0
    total_my_predictions = 0
    total_my_maliciousbot = 0
    total_my_scan_indicators = 0

    all_dbs_to_check = [uinfo['name'] for uinfo in user_db_map.values()] + [guest_db]
    for dbn in all_dbs_to_check:
        c = get_mysql_conn(dbn)
        cur = c.cursor()
        cur.execute("SELECT COUNT(*) FROM pari_scan")
        total_my_scans += cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM pari_prediction")
        total_my_predictions += cur.fetchone()[0]
        try:
            cur.execute("SELECT COUNT(*) FROM User_maliciousbot")
            total_my_maliciousbot += cur.fetchone()[0]
        except Exception:
            pass
        cur.execute("SELECT COUNT(*) FROM pari_scan_indicator")
        total_my_scan_indicators += cur.fetchone()[0]
        c.close()

    print(f"pari_scan (Sum across all DBs)  : SQLite={sqlite_counts['pari_scan']}, MySQL={total_my_scans} -> MATCH: {sqlite_counts['pari_scan'] == total_my_scans}")
    print(f"pari_prediction (All DBs)       : SQLite={sqlite_counts['pari_prediction']}, MySQL={total_my_predictions} -> MATCH: {sqlite_counts['pari_prediction'] == total_my_predictions}")
    print(f"User_maliciousbot (All DBs)     : SQLite={sqlite_counts['User_maliciousbot']}, MySQL={total_my_maliciousbot} -> MATCH: {sqlite_counts['User_maliciousbot'] == total_my_maliciousbot}")
    print(f"pari_scan_indicator (All DBs)   : SQLite={sqlite_counts['pari_scan_indicator']}, MySQL={total_my_scan_indicators} -> MATCH: {sqlite_counts['pari_scan_indicator'] == total_my_scan_indicators}")

    m_conn_core.close()
    s_conn.close()

    print("\n" + "=" * 70)
    print("MIGRATION TO MYSQL COMPLETED SUCCESSFULLY!")
    print("=" * 70)

if __name__ == '__main__':
    run_migration()
