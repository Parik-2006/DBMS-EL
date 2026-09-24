"""
Real Browser E2E Test Suite using Playwright.
Automates complete browser verification across login, predict, confident ML,
uncertain NPTEL fallback, 6 collectors, AI status, history, search, filters,
long URL rendering, logout, and MongoDB Atlas + SQL cross-database consistency.
"""
import os
import sys
import time
import unittest
import django

# Setup Django environment
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'MaliciousBot.settings')
os.environ["DJANGO_ALLOW_ASYNC_UNSAFE"] = "true"
django.setup()

from django.contrib.auth.models import User
from User.models import Scan, Prediction, MaliciousBot
from User.services.nikhil.mongodb_repository import MongoDBRepository

from playwright.sync_api import sync_playwright


class TestBrowserE2E(unittest.TestCase):
    """Real Browser E2E Tests for PARI + Nikhil Fallback Architecture."""

    BASE_URL = "http://127.0.0.1:8000"
    USERNAME = "e2e_user"
    PASSWORD = "E2ePassword123!"

    @classmethod
    def setUpClass(cls):
        # Ensure test user exists with known password
        u, _ = User.objects.get_or_create(username=cls.USERNAME, defaults={"email": "e2e@example.com"})
        u.set_password(cls.PASSWORD)
        u.save()

        # Start Playwright and Browser
        cls.playwright = sync_playwright().start()
        cls.browser = cls.playwright.chromium.launch(headless=True)

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.playwright.stop()

    def setUp(self):
        self.context = self.browser.new_context(viewport={"width": 1280, "height": 900})
        self.page = self.context.new_page()

    def tearDown(self):
        self.context.close()

    def _login(self):
        """Helper to log into the application."""
        self.page.goto(f"{self.BASE_URL}/login")
        self.page.fill('input[name="username"]', self.USERNAME)
        self.page.fill('input[name="password"]', self.PASSWORD)
        self.page.click('button[type="submit"]')
        self.page.wait_for_load_state("networkidle")

    def test_01_login_flow(self):
        """Verify login page loads, authentication succeeds, and redirects to predict."""
        self.page.goto(f"{self.BASE_URL}/login")
        self.assertTrue(self.page.locator('input[name="username"]').is_visible())
        self.assertTrue(self.page.locator('input[name="password"]').is_visible())

        self.page.fill('input[name="username"]', self.USERNAME)
        self.page.fill('input[name="password"]', self.PASSWORD)
        self.page.click('button[type="submit"]')
        self.page.wait_for_load_state("networkidle")

        # Expect redirect to /predict
        self.assertIn("/predict", self.page.url)
        content = self.page.content()
        self.assertIn(f"Welcome {self.USERNAME}", content)

    def test_02_predict_page_elements(self):
        """Verify predict page form controls and layout."""
        self._login()
        self.page.goto(f"{self.BASE_URL}/predict")
        self.assertTrue(self.page.locator('textarea[name="url"]').is_visible())
        self.assertTrue(self.page.locator('button.predict-submit-btn').is_visible())

    def test_03_confident_scan(self):
        """Verify confident URL evaluates purely in Stage 1 without invoking Nikhil fallback."""
        self._login()
        self.page.goto(f"{self.BASE_URL}/predict")

        confident_url = "http://secure-login-bank-verification.com/login.html"
        self.page.fill('textarea[name="url"]', confident_url)
        self.page.click('button.predict-submit-btn')
        self.page.wait_for_load_state("networkidle")

        content = self.page.content()
        self.assertIn("CONFIDENT", content)
        self.assertIn("INITIAL ML EVALUATION", content)
        # Stage 2 (fallback deep analysis) must NOT be present
        self.assertNotIn("STAGE 2 &mdash; DEEP EVIDENCE COLLECTION", content)
        self.assertNotIn("Nikhil Fallback", content)

    def test_04_uncertain_nptel_scan_and_all_stages(self):
        """
        Verify uncertain NPTEL URL:
        - Routes to Nikhil fallback (< 75% threshold)
        - Displays Stage 1 (Initial ML assessment)
        - Displays Stage 2 (All 6 collectors visible + AI status)
        - Displays Stage 3 (Corroboration & evidence families)
        - Displays Stage 4 (Final classification & risk)
        - Database persistence in SQL and MongoDB Atlas
        """
        self._login()
        self.page.goto(f"{self.BASE_URL}/predict")

        nptel_url = "https://onlinecourses.nptel.ac.in/e-learning/course/noc26_hs247?unitId=38&lessonId=39"
        self.page.fill('textarea[name="url"]', nptel_url)
        
        # Submit and wait for deep analysis (which does network, DOM, SSL, AI)
        self.page.click('button.predict-submit-btn')
        self.page.wait_for_selector('.report-container', timeout=60000)

        content = self.page.content()

        # STAGE 1: Initial ML Assessment
        self.assertIn("STAGE 1", content)
        self.assertIn("UNCERTAIN", content)
        self.assertIn("Initial ML Prediction:", content)
        self.assertIn("routed to Nikhil Fallback", content)

        # STAGE 2: Exactly the six collectors
        self.assertIn("Webpage Analysis", content)
        self.assertIn("Network Analysis", content)
        self.assertIn("Visual Analysis", content)
        self.assertIn("Threat Intelligence", content)
        self.assertIn("Prompt Injection", content)
        self.assertIn("AI Analysis", content)

        # Verify AI status is a valid status string (not blank or fake)
        valid_ai_statuses = ["SUCCESS", "NOT RUN", "UNAVAILABLE", "RATE LIMITED", "QUOTA EXCEEDED", "ERROR"]
        has_valid_ai = any(st in content for st in valid_ai_statuses)
        self.assertTrue(has_valid_ai, "AI status must display one of the defined valid statuses")

        # STAGE 3: Corroboration
        self.assertIn("STAGE 3", content)
        self.assertIn("EVIDENCE CORROBORATION", content)
        self.assertIn("Evidence Families Used:", content)
        self.assertIn("Evidence Summary:", content)

        # STAGE 4: Final Classification
        self.assertIn("STAGE 4", content)
        self.assertIn("FINAL FALLBACK CLASSIFICATION", content)
        self.assertIn("RISK: LOW", content)
        self.assertIn("Benign", content)

        # Verify SQL & MongoDB Atlas consistency
        latest_scan = Scan.objects.order_by("-id").first()
        self.assertIsNotNone(latest_scan)
        self.assertEqual(latest_scan.status, "COMPLETED")

        pred = latest_scan.prediction
        self.assertIsNotNone(pred)
        self.assertEqual(pred.predicted_class, "Benign")

        # Real MongoDB Atlas Document Check
        repo = MongoDBRepository()
        self.assertTrue(repo.is_available(), "MongoDB Atlas connection must be live")
        atlas_doc = repo.collection.find_one({"scan_id": latest_scan.id})
        self.assertIsNotNone(atlas_doc, f"Scan {latest_scan.id} must be persisted in Atlas collection")

        self.assertEqual(atlas_doc.get("scan_id"), latest_scan.id)
        self.assertEqual(atlas_doc.get("final_analysis", {}).get("classification"), pred.predicted_class)
        self.assertAlmostEqual(atlas_doc.get("final_analysis", {}).get("risk_score"), pred.risk_score, places=2)

    def test_05_history_page_design_search_filters_and_long_url(self):
        """Verify redesigned history page: full width, no image, search, filters, and long URL display."""
        self._login()
        self.page.goto(f"{self.BASE_URL}/data")
        self.page.wait_for_load_state("networkidle")

        content = self.page.content()

        # STEP 8: Verify layout & no typewriter image
        self.assertNotIn("contact-img.jpg", content)
        self.assertTrue(self.page.locator('.history-table').is_visible())
        self.assertTrue(self.page.locator('#searchInput').is_visible())

        # STEP 9: Search functionality
        self.page.fill('#searchInput', 'nptel.ac.in')
        time.sleep(0.5)
        visible_rows = self.page.locator('#historyBody tr:visible')
        self.assertGreaterEqual(visible_rows.count(), 1)
        for i in range(visible_rows.count()):
            row_text = visible_rows.nth(i).inner_text().lower()
            self.assertIn("nptel", row_text)

        # Reset search
        self.page.fill('#searchInput', '')
        time.sleep(0.3)

        # STEP 10: Category Filters
        benign_btn = self.page.locator('.filter-btn[data-filter="Benign"]')
        benign_btn.click()
        time.sleep(0.3)
        benign_rows = self.page.locator('#historyBody tr:visible')
        for i in range(benign_rows.count()):
            badge_text = benign_rows.nth(i).locator('.badge-type').inner_text()
            self.assertEqual(badge_text.strip().upper(), "BENIGN")

        # Click All filter
        self.page.locator('.filter-btn[data-filter="all"]').click()
        time.sleep(0.3)

        # STEP 11: Long URL layout integrity
        url_cells = self.page.locator('.url-cell')
        self.assertGreaterEqual(url_cells.count(), 1)
        # Verify first url cell does not have broken width
        box = url_cells.first.bounding_box()
        self.assertIsNotNone(box)
        self.assertGreater(box['width'], 100)

    def test_06_logout(self):
        """Verify logout button terminates session."""
        self._login()
        self.page.goto(f"{self.BASE_URL}/predict")
        self.page.click('a[href="/logout"]')
        self.page.wait_for_load_state("networkidle")

        # Navbar should now show Login link and not Logout
        self.assertTrue(self.page.locator('.navbar-nav a[href="/login"]').is_visible())
        self.assertFalse(self.page.locator('.navbar-nav a[href="/logout"]').is_visible())

        # Accessing protected history page must redirect to /login
        self.page.goto(f"{self.BASE_URL}/data")
        self.assertIn("/login", self.page.url)


if __name__ == "__main__":
    unittest.main()
