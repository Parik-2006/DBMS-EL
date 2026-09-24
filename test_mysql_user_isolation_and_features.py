import os
import django
import MySQLdb

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'MaliciousBot.settings')
django.setup()

from django.conf import settings
from django.contrib.auth.models import User
from django.test import Client
from django.utils import timezone
from User.models import (
    Domain, URL, Scan, Prediction, ThreatIndicator, ScanIndicator,
    MaliciousBot, UserDatabaseRegistry, HistoryClearEvent
)
from User.db_manager import (
    ensure_user_database, set_current_db, reset_current_db,
    get_user_db_name, get_mysql_server_config
)

def run_tests():
    print("=" * 70)
    print("COMPREHENSIVE MYSQL USER ISOLATION & CLEAR HISTORY TEST SUITE")
    print("=" * 70)

    cfg = get_mysql_server_config()
    
    # -------------------------------------------------------------
    # TEST 1: MySQL Server Connection & Version
    # -------------------------------------------------------------
    print("\n--- TEST 1: MySQL Server Connection & Version ---")
    conn = MySQLdb.connect(
        host=cfg['HOST'], port=cfg['PORT'], user=cfg['USER'], passwd=cfg['PASSWORD']
    )
    conn.autocommit(True)
    cur = conn.cursor()
    cur.execute("SELECT VERSION()")

    version = cur.fetchone()[0]
    print(f"Connected to MySQL version: {version}")
    assert version.startswith('8.') or '8.0' in version, f"Expected MySQL 8.0+, got {version}"
    print("TEST 1 PASSED: MySQL 8.0+ verified.")

    # -------------------------------------------------------------
    # TEST 2: Control DB & User Registry
    # -------------------------------------------------------------
    print("\n--- TEST 2: Control Database & Registries ---")
    cur.execute("SHOW DATABASES LIKE 'maliciousbot_%'")
    dbs = [r[0] for r in cur.fetchall()]
    print(f"Active MaliciousBot databases: {dbs}")
    assert 'maliciousbot_core' in dbs, "maliciousbot_core missing!"
    assert 'maliciousbot_guest' in dbs, "maliciousbot_guest missing!"

    registries = list(UserDatabaseRegistry.objects.using('default').all())
    print(f"Total registered user databases in maliciousbot_core: {len(registries)}")
    for r in registries:
        print(f"  User {r.username} (ID {r.user_id}) -> {r.database_name}")
    assert len(registries) >= 6, "Expected at least 6 migrated user registries!"
    print("TEST 2 PASSED: Control DB & registries verified.")

    # -------------------------------------------------------------
    # TEST 3: User Creation & Automated Database Provisioning
    # -------------------------------------------------------------
    print("\n--- TEST 3: User Registration & Dynamic DB Provisioning ---")
    uname_a = f"test_iso_a_{int(timezone.now().timestamp())}"
    uname_b = f"test_iso_b_{int(timezone.now().timestamp())}"

    # Create User A
    user_a = User.objects.create_user(
        username=uname_a, password='Password123!', email=f"{uname_a}@example.com"
    )
    db_alias_a = ensure_user_database(user_a)
    db_name_a = get_user_db_name(user_a.id)

    # Create User B
    user_b = User.objects.create_user(
        username=uname_b, password='Password123!', email=f"{uname_b}@example.com"
    )

    db_alias_b = ensure_user_database(user_b)
    db_name_b = get_user_db_name(user_b.id)

    print(f"User A: {user_a.username} (ID {user_a.id}) -> DB: {db_name_a}")
    print(f"User B: {user_b.username} (ID {user_b.id}) -> DB: {db_name_b}")

    # Verify both databases exist physically in MySQL
    cur.execute(f"SHOW DATABASES LIKE '{db_name_a}'")
    assert cur.fetchone() is not None, f"Database {db_name_a} not found in MySQL!"
    cur.execute(f"SHOW DATABASES LIKE '{db_name_b}'")
    assert cur.fetchone() is not None, f"Database {db_name_b} not found in MySQL!"

    # Verify registries in maliciousbot_core
    reg_a = UserDatabaseRegistry.objects.using('default').get(user_id=user_a.id)
    reg_b = UserDatabaseRegistry.objects.using('default').get(user_id=user_b.id)
    assert reg_a.database_name == db_name_a
    assert reg_b.database_name == db_name_b
    print("TEST 3 PASSED: Dynamic provisioning and registry verified.")

    # -------------------------------------------------------------
    # TEST 4: Physical Data Isolation (User A vs User B)
    # -------------------------------------------------------------
    print("\n--- TEST 4: Physical User Data Isolation ---")
    # In context of User A
    token = set_current_db(db_alias_a)
    try:
        dom_a, _ = Domain.objects.get_or_create(domain_name="usera-exclusive.org")
        url_a1, _ = URL.objects.get_or_create(url="https://usera-exclusive.org/page1", domain=dom_a)
        url_a2, _ = URL.objects.get_or_create(url="https://usera-exclusive.org/page2", domain=dom_a)
        
        scan_a1 = Scan.objects.create(url=url_a1, status="CONFIDENT", user=user_a)
        pred_a1 = Prediction.objects.create(scan=scan_a1, model_name="RandomForest", predicted_class="Benign", confidence=0.98, risk_score=0.02)
        mb_a1 = MaliciousBot.objects.create(user=user_a, url=url_a1.url, prediction="Benign", prediction_type="Benign", confidence="98.00%")
        
        scan_a2 = Scan.objects.create(url=url_a2, status="CONFIDENT", user=user_a)
        pred_a2 = Prediction.objects.create(scan=scan_a2, model_name="RandomForest", predicted_class="Phishing", confidence=0.89, risk_score=0.85)
        mb_a2 = MaliciousBot.objects.create(user=user_a, url=url_a2.url, prediction="Phishing", prediction_type="Phishing", confidence="89.00%")
        
        count_a_scans = Scan.objects.count()
        count_a_mb = MaliciousBot.objects.count()
        print(f"User A DB: {count_a_scans} scans, {count_a_mb} bot rows.")
        assert count_a_scans == 2
        assert count_a_mb == 2
    finally:
        reset_current_db(token)

    # In context of User B
    token = set_current_db(db_alias_b)
    try:
        dom_b, _ = Domain.objects.get_or_create(domain_name="userb-private.net")
        url_b1, _ = URL.objects.get_or_create(url="https://userb-private.net/portal", domain=dom_b)
        url_b2, _ = URL.objects.get_or_create(url="https://userb-private.net/login", domain=dom_b)
        
        scan_b1 = Scan.objects.create(url=url_b1, status="CONFIDENT", user=user_b)
        pred_b1 = Prediction.objects.create(scan=scan_b1, model_name="RandomForest", predicted_class="Malware", confidence=0.92, risk_score=0.95)
        mb_b1 = MaliciousBot.objects.create(user=user_b, url=url_b1.url, prediction="Malware", prediction_type="Malware", confidence="92.00%")
        
        scan_b2 = Scan.objects.create(url=url_b2, status="CONFIDENT", user=user_b)
        pred_b2 = Prediction.objects.create(scan=scan_b2, model_name="RandomForest", predicted_class="Defacement", confidence=0.85, risk_score=0.80)
        mb_b2 = MaliciousBot.objects.create(user=user_b, url=url_b2.url, prediction="Defacement", prediction_type="Defacement", confidence="85.00%")
        
        count_b_scans = Scan.objects.count()
        count_b_mb = MaliciousBot.objects.count()
        print(f"User B DB: {count_b_scans} scans, {count_b_mb} bot rows.")
        assert count_b_scans == 2
        assert count_b_mb == 2

        # Verify User B CANNOT see User A's scans
        assert not Scan.objects.filter(url__url=url_a1.url).exists(), "Isolation failure: User B found URL A1!"
        assert not Scan.objects.filter(url__url=url_a2.url).exists(), "Isolation failure: User B found URL A2!"
        assert not MaliciousBot.objects.filter(url=url_a1.url).exists(), "Isolation failure: User B found URL A1 in bot table!"
        assert not URL.objects.filter(url=url_a1.url).exists(), "Isolation failure: User B found URL object A1!"
    finally:
        reset_current_db(token)

    # In context of User A again
    token = set_current_db(db_alias_a)
    try:
        # Verify User A CANNOT see User B's scans
        assert not Scan.objects.filter(url__url=url_b1.url).exists(), "Isolation failure: User A found URL B1!"
        assert not Scan.objects.filter(url__url=url_b2.url).exists(), "Isolation failure: User A found URL B2!"
        assert not MaliciousBot.objects.filter(url=url_b1.url).exists(), "Isolation failure: User A found URL B1 in bot table!"
        assert not URL.objects.filter(url=url_b1.url).exists(), "Isolation failure: User A found URL object B1!"
    finally:
        reset_current_db(token)


    # Directly verify in MySQL via raw queries
    cur.execute(f"SELECT COUNT(*) FROM `{db_name_a}`.pari_scan")
    raw_cnt_a = cur.fetchone()[0]
    cur.execute(f"SELECT COUNT(*) FROM `{db_name_b}`.pari_scan")
    raw_cnt_b = cur.fetchone()[0]
    assert raw_cnt_a == 2, f"Expected 2 rows in {db_name_a}, got {raw_cnt_a}"
    assert raw_cnt_b == 2, f"Expected 2 rows in {db_name_b}, got {raw_cnt_b}"
    print(f"Direct MySQL verification: {db_name_a} has {raw_cnt_a} scans; {db_name_b} has {raw_cnt_b} scans.")
    print("TEST 4 PASSED: Mutual data isolation verified.")

    # -------------------------------------------------------------
    # TEST 5: Non-Destructive Clear History
    # -------------------------------------------------------------
    print("\n--- TEST 5: Non-Destructive Clear History ---")
    client_a = Client()
    client_a.force_login(user_a)

    def count_visible_history(resp):
        if resp.context is not None and 'data' in resp.context:
            return len(resp.context['data'])
        html = resp.content.decode()
        if 'No Prediction History' in html:
            return 0
        return html.count('class="url-cell"')

    # 5a. View history before clearing
    resp = client_a.get('/data')
    assert resp.status_code == 200
    visible_before = count_visible_history(resp)
    assert visible_before == 2, f"Expected 2 items in history, got {visible_before}"
    print(f"History before clear: {visible_before} scans visible in UI.")

    # 5b. User A clears history via POST /clear-history
    resp_clear = client_a.post('/clear-history', follow=True)
    assert resp_clear.status_code == 200
    print("POST /clear-history executed.")

    # 5c. Check UI state immediately after clear
    resp_after = client_a.get('/data')
    assert resp_after.status_code == 200
    visible_after = count_visible_history(resp_after)
    assert visible_after == 0, f"Expected 0 items visible after clear, got {visible_after}"
    assert "No Prediction History" in resp_after.content.decode()
    print("History UI immediately after clear: 0 scans visible (empty state shown).")

    # 5d. Check MySQL directly: ALL ROWS MUST STILL EXIST!
    cur.execute(f"SELECT COUNT(*) FROM `{db_name_a}`.pari_scan")
    db_cnt_after = cur.fetchone()[0]
    cur.execute(f"SELECT COUNT(*) FROM `{db_name_a}`.user_maliciousbot")
    mb_cnt_after = cur.fetchone()[0]
    cur.execute(f"SELECT COUNT(*) FROM `{db_name_a}`.history_clear_events")
    clear_events_cnt = cur.fetchone()[0]

    assert db_cnt_after == 2, f"DESTRUCTIVE VIOLATION! Expected 2 scans in DB, found {db_cnt_after}"
    assert mb_cnt_after == 2, f"DESTRUCTIVE VIOLATION! Expected 2 MaliciousBot rows, found {mb_cnt_after}"
    assert clear_events_cnt >= 1, "Expected history_clear_events record!"
    print(f"MySQL direct check: DB still contains {db_cnt_after} scans and {mb_cnt_after} bot rows! ZERO DELETIONS.")

    # 5e. User A performs a new scan after clearing history
    token = set_current_db(db_alias_a)
    try:
        dom_a3, _ = Domain.objects.get_or_create(domain_name="usera-newscan.org")
        url_a3, _ = URL.objects.get_or_create(url="https://usera-newscan.org/brand-new", domain=dom_a3)
        scan_a3 = Scan.objects.create(url=url_a3, status="CONFIDENT", user=user_a)
        pred_a3 = Prediction.objects.create(scan=scan_a3, model_name="RandomForest", predicted_class="Benign", confidence=0.99, risk_score=0.01)
        mb_a3 = MaliciousBot.objects.create(user=user_a, url=url_a3.url, prediction="Benign", prediction_type="Benign", confidence="99.00%")
    finally:
        reset_current_db(token)

    # 5f. View history again: ONLY the new scan (A3) should be visible!
    resp_new = client_a.get('/data')
    assert resp_new.status_code == 200
    visible_new = count_visible_history(resp_new)
    assert visible_new == 1, f"Expected exactly 1 new item visible, got {visible_new}"
    assert "https://usera-newscan.org/brand-new" in resp_new.content.decode()
    print(f"History UI after new scan: exactly 1 new scan visible (https://usera-newscan.org/brand-new).")

    # In MySQL: A1, A2, A3 all exist!
    cur.execute(f"SELECT COUNT(*) FROM `{db_name_a}`.pari_scan")
    assert cur.fetchone()[0] == 3, "Expected 3 total scans in MySQL!"
    print("MySQL direct check: all 3 scans (2 old + 1 new) permanently stored.")

    # 5g. Persistence across Logout and Login
    client_a.logout()
    client_a.force_login(user_a)
    resp_relogin = client_a.get('/data')
    assert count_visible_history(resp_relogin) == 1, "Expected clear marker to persist across logout/login!"
    print("Persistence check: Clear history marker persisted across logout and login.")

    # 5h. Cross-user isolation of clear history: User B is completely unaffected!
    client_b = Client()
    client_b.force_login(user_b)
    resp_b = client_b.get('/data')
    assert resp_b.status_code == 200
    visible_b = count_visible_history(resp_b)
    assert visible_b == 2, f"User B history was affected! Expected 2, got {visible_b}"
    print("Cross-user clear test: User B history remains completely intact (2 scans visible).")
    print("TEST 5 PASSED: Non-destructive clear history verified.")

    # -------------------------------------------------------------
    # TEST 6: API Cross-User Security Isolation
    # -------------------------------------------------------------
    print("\n--- TEST 6: API Security & ID Tampering Protection ---")
    # User B attempts to access User A's scan 3 (which only exists in User A's DB)
    resp_tamper = client_b.get(f'/api/nikhil/investigation/{scan_a3.id}/')
    assert resp_tamper.status_code == 404, f"Security leak! User B accessed User A's scan: {resp_tamper.content}"
    assert resp_tamper.json()['success'] is False

    # User B attempts to access scan status for scan 3
    resp_status_tamper = client_b.get(f'/api/fallback/scan-status/{scan_a3.id}/')
    assert resp_status_tamper.status_code == 404, f"Security leak! User B accessed scan status: {resp_status_tamper.content}"
    assert resp_status_tamper.json()['success'] is False

    # User B accesses ID 1: returns User B's URL, NEVER User A's URL!
    resp_b1 = client_b.get(f'/api/nikhil/investigation/{scan_b1.id}/')
    assert resp_b1.status_code == 200
    assert resp_b1.json()['url'] == url_b1.url, "URL mismatch in User B's scan!"
    assert resp_b1.json()['url'] != url_a1.url, "Security leak! User B saw User A's URL!"

    print("API tamper test: Direct scan_id manipulation and URL isolation verified.")
    print("TEST 6 PASSED: API isolation verified.")


    conn.close()
    print("\n" + "=" * 70)
    print("ALL TESTS IN TEST SUITE PASSED SUCCESSFULLY!")
    print("=" * 70)

if __name__ == '__main__':
    run_tests()
