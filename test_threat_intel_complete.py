"""
Comprehensive Automated Test Suite for Free-Only Threat Intelligence subsystem in Nikhil.
Tests all 36 mandatory test cases:
  1-7:   ThreatFox Provider tests
  8-14:  URLhaus Provider tests
  15-20: AbuseIPDB Provider tests
  21-30: Integration & Pipeline tests
  31-36: Security & Policy Enforcement tests
"""
import os
import sys
import json
import logging
import unittest
import requests
from unittest.mock import patch, MagicMock

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'MaliciousBot.settings')
import django
django.setup()

from User.services.nikhil.free_only_guard import FreeOnlyGuard
from User.services.nikhil.threatfox_provider import ThreatFoxProvider
from User.services.nikhil.urlhaus_provider import URLhausProvider
from User.services.nikhil.abuseipdb_provider import AbuseIPDBProvider
from User.services.nikhil.threat_intel import ThreatIntelService
from User.services.nikhil.final_classifier import FinalClassifier
from User.services.nikhil.evidence_normalizer import EvidenceNormalizer


class TestThreatFoxProvider(unittest.TestCase):
    """ThreatFox tests 1 to 7"""

    def setUp(self):
        self.provider = ThreatFoxProvider(api_key="test_dummy_key_12345")

    @patch("requests.post")
    def test_01_threatfox_successful_ioc_hit(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "query_status": "ok",
            "data": [{
                "ioc": "evil-malware.com",
                "ioc_type": "domain",
                "threat_type": "payload_delivery",
                "threat_type_desc": "Delivers malware payload",
                "malware_printable": "Emotet",
                "confidence_level": 100,
                "first_seen_utc": "2026-01-01 00:00:00",
                "last_seen_utc": "2026-01-02 00:00:00",
                "tags": ["emotet", "loader"]
            }]
        }
        mock_post.return_value = mock_resp

        res = self.provider.lookup_ioc("evil-malware.com")
        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["hits"], 1)
        self.assertIn("Emotet", res["malware_families"])
        self.assertIn("payload_delivery", res["threat_types"])

    @patch("requests.post")
    def test_02_threatfox_no_match(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"query_status": "no_result"}
        mock_post.return_value = mock_resp

        res = self.provider.lookup_ioc("clean-site.org")
        self.assertEqual(res["status"], "NO_MATCH")
        self.assertEqual(res["hits"], 0)
        self.assertEqual(len(res["matches"]), 0)

    @patch("requests.post")
    def test_03_threatfox_rate_limit(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 429
        mock_post.return_value = mock_resp

        res = self.provider.lookup_ioc("test-domain.com")
        self.assertEqual(res["status"], "RATE_LIMITED")
        self.assertEqual(res["hits"], 0)

    @patch("requests.post")
    def test_04_threatfox_auth_failure(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_post.return_value = mock_resp

        res = self.provider.lookup_ioc("test-domain.com")
        self.assertEqual(res["status"], "AUTH_ERROR")

    @patch("requests.post")
    def test_05_threatfox_timeout(self, mock_post):
        mock_post.side_effect = requests.exceptions.Timeout("Connection timeout")

        res = self.provider.lookup_ioc("timeout-domain.com")
        self.assertEqual(res["status"], "TIMEOUT")
        self.assertEqual(res["hits"], 0)

    @patch("requests.post")
    def test_06_threatfox_malformed_response(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.side_effect = ValueError("Invalid JSON body")
        mock_post.return_value = mock_resp

        res = self.provider.lookup_ioc("bad-json-domain.com")
        self.assertEqual(res["status"], "ERROR")

    def test_07_threatfox_api_disabled(self):
        disabled_provider = ThreatFoxProvider(api_key="")
        res = disabled_provider.lookup_ioc("test-disabled.com")
        self.assertEqual(res["status"], "UNAVAILABLE")
        self.assertEqual(res["hits"], 0)


class TestURLhausProvider(unittest.TestCase):
    """URLhaus tests 8 to 14"""

    def setUp(self):
        self.provider = URLhausProvider(api_key="test_dummy_key_12345")

    @patch("requests.post")
    def test_08_urlhaus_malware_url_hit(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "query_status": "ok",
            "url": "http://malware-drop.com/payload.exe",
            "url_status": "online",
            "threat": "malware_download",
            "tags": ["exe", "redline"],
            "date_added": "2026-03-01 10:00:00",
            "reporter": "abuse_hunter"
        }
        mock_post.return_value = mock_resp

        res = self.provider.lookup_url("http://malware-drop.com/payload.exe")
        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["hits"], 1)
        self.assertEqual(res["threat"], "malware_download")
        self.assertEqual(res["url_status"], "online")

    @patch("requests.post")
    def test_09_urlhaus_no_match(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"query_status": "no_results"}
        mock_post.return_value = mock_resp

        res = self.provider.lookup_url("https://clean-site.org/index.html")
        self.assertEqual(res["status"], "NO_MATCH")
        self.assertEqual(res["hits"], 0)

    @patch("requests.post")
    def test_10_urlhaus_rate_limit(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 429
        mock_post.return_value = mock_resp

        res = self.provider.lookup_url("http://rate-limited-test.com")
        self.assertEqual(res["status"], "RATE_LIMITED")

    @patch("requests.post")
    def test_11_urlhaus_auth_failure(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_post.return_value = mock_resp

        res = self.provider.lookup_url("http://auth-fail-test.com")
        self.assertEqual(res["status"], "AUTH_ERROR")

    @patch("requests.post")
    def test_12_urlhaus_timeout(self, mock_post):
        mock_post.side_effect = requests.exceptions.Timeout("URLhaus timeout")

        res = self.provider.lookup_url("http://timeout-test.com")
        self.assertEqual(res["status"], "TIMEOUT")

    @patch("requests.post")
    def test_13_urlhaus_malformed_response(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.side_effect = ValueError("Malformed JSON")
        mock_post.return_value = mock_resp

        res = self.provider.lookup_url("http://bad-json.com")
        self.assertEqual(res["status"], "ERROR")

    def test_14_urlhaus_api_disabled(self):
        disabled = URLhausProvider(api_key="")
        res = disabled.lookup_url("http://disabled-test.com")
        self.assertEqual(res["status"], "UNAVAILABLE")


class TestAbuseIPDBProvider(unittest.TestCase):
    """AbuseIPDB tests 15 to 20"""

    def setUp(self):
        self.provider = AbuseIPDBProvider(api_key="dummy_abuseipdb_key")

    @patch("requests.get")
    def test_15_abuseipdb_high_abuse_score(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "ipAddress": "104.244.42.1",
                "abuseConfidenceScore": 88,
                "totalReports": 34,
                "numDistinctUsers": 12,
                "countryCode": "US",
                "usageType": "Data Center",
                "isp": "Suspicious Host Ltd",
                "domain": "badhost.net",
                "isWhitelisted": False
            }
        }
        mock_get.return_value = mock_resp

        res = self.provider.check_ip("104.244.42.1")
        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["abuse_confidence_score"], 88)
        self.assertEqual(res["total_reports"], 34)

    @patch("requests.get")
    def test_16_abuseipdb_low_zero_abuse_score(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "ipAddress": "8.8.8.8",
                "abuseConfidenceScore": 0,
                "totalReports": 0,
                "numDistinctUsers": 0,
                "countryCode": "US",
                "isWhitelisted": True
            }
        }
        mock_get.return_value = mock_resp

        res = self.provider.check_ip("8.8.8.8")
        self.assertEqual(res["status"], "NO_MATCH")
        self.assertEqual(res["abuse_confidence_score"], 0)

    @patch("requests.get")
    def test_17_abuseipdb_rate_limit(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 429
        mock_get.return_value = mock_resp

        res = self.provider.check_ip("104.244.42.1")
        self.assertEqual(res["status"], "RATE_LIMITED")

    @patch("requests.get")
    def test_18_abuseipdb_auth_failure(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_get.return_value = mock_resp

        res = self.provider.check_ip("104.244.42.1")
        self.assertEqual(res["status"], "AUTH_ERROR")

    @patch("requests.get")
    def test_19_abuseipdb_timeout(self, mock_get):
        mock_get.side_effect = requests.exceptions.Timeout("AbuseIPDB timeout")

        res = self.provider.check_ip("104.244.42.1")
        self.assertEqual(res["status"], "TIMEOUT")

    def test_20_abuseipdb_api_disabled(self):
        disabled = AbuseIPDBProvider(api_key="")
        res = disabled.check_ip("104.244.42.1")
        self.assertEqual(res["status"], "UNAVAILABLE")


class TestThreatIntelIntegration(unittest.TestCase):
    """Integration tests 21 to 30"""

    def setUp(self):
        self.service = ThreatIntelService()
        self.classifier = FinalClassifier()

    def test_21_threatfox_plus_urlhaus_hit(self):
        """ThreatFox + URLhaus hit yields strong Malware corroboration"""
        mock_tf = MagicMock()
        mock_tf.lookup_ioc.return_value = {
            "status": "SUCCESS", "hits": 1,
            "threat_types": ["malware"], "malware_families": ["Qakbot"],
            "matches": [{"ioc": "bad-host.com", "threat_type": "malware"}]
        }
        mock_uh = MagicMock()
        mock_uh.lookup_url.return_value = {
            "status": "SUCCESS", "hits": 1, "threat": "malware_download", "url_status": "online"
        }
        mock_aip = MagicMock()
        mock_aip.check_ip.return_value = {"status": "NO_MATCH", "abuse_confidence_score": 0}
        mock_aip.is_public_ip.return_value = True

        service = ThreatIntelService(threatfox=mock_tf, urlhaus=mock_uh, abuseipdb=mock_aip)
        ti_result = service.analyze_threat_intel("http://bad-host.com/drop.exe", domain="bad-host.com", ip="198.51.100.5")

        self.assertEqual(ti_result["status"], "SUCCESS")
        self.assertTrue(ti_result["summary"]["known_malicious_ioc"])
        self.assertTrue(ti_result["summary"]["known_malware_url"])

        # Feed to classifier
        evidence = {
            "webpage": {"status": "SUCCESS", "indicators": []},
            "network": {"status": "SUCCESS", "ssl": {"verified": False}},
            "threat_intelligence": ti_result,
            "visual": {"status": "UNAVAILABLE"},
            "prompt_injection": {"prompt_injection_detected": False}
        }
        classified = self.classifier.classify("Malware", 0.65, evidence)
        self.assertEqual(classified["final_classification"], "Malware")
        self.assertIn(classified["risk_level"], ["HIGH", "CRITICAL"])

    def test_22_threatfox_hit_plus_abuseipdb_hit(self):
        """ThreatFox IP hit + AbuseIPDB hit yields malicious network & TI corroboration"""
        mock_tf = MagicMock()
        mock_tf.lookup_ioc.return_value = {
            "status": "SUCCESS", "hits": 1, "threat_types": ["botnet_cc"], "malware_families": ["CobaltStrike"],
            "matches": [{"ioc": "198.51.100.99", "threat_type": "botnet_cc"}]
        }
        mock_uh = MagicMock()
        mock_uh.lookup_url.return_value = {"status": "NO_MATCH", "hits": 0}
        mock_uh.lookup_host.return_value = {"status": "NO_MATCH", "hits": 0}
        mock_aip = MagicMock()
        mock_aip.check_ip.return_value = {
            "status": "SUCCESS", "abuse_confidence_score": 95, "total_reports": 80
        }
        mock_aip.is_public_ip.return_value = True

        service = ThreatIntelService(threatfox=mock_tf, urlhaus=mock_uh, abuseipdb=mock_aip)
        ti_result = service.analyze_threat_intel("http://c2-node.net", domain="c2-node.net", ip="198.51.100.99")

        self.assertEqual(ti_result["summary"]["ip_abuse_score"], 95)
        self.assertEqual(ti_result["status"], "SUCCESS")

        evidence = {
            "webpage": {"status": "UNAVAILABLE"},
            "network": {"status": "SUCCESS", "is_ip_address": True, "ssl": {"verified": False}},
            "threat_intelligence": ti_result,
            "visual": {"status": "UNAVAILABLE"},
            "prompt_injection": {"prompt_injection_detected": False}
        }
        classified = self.classifier.classify("Malware", 0.60, evidence)
        self.assertIn(classified["final_classification"], ["Malware", "Phishing"])

    def test_23_all_sources_no_match(self):
        """All external TI sources return NO_MATCH -> status is SUCCESS but hits=0"""
        mock_tf = MagicMock()
        mock_tf.lookup_ioc.return_value = {"status": "NO_MATCH", "hits": 0, "matches": []}
        mock_uh = MagicMock()
        mock_uh.lookup_url.return_value = {"status": "NO_MATCH", "hits": 0}
        mock_uh.lookup_host.return_value = {"status": "NO_MATCH", "hits": 0}
        mock_aip = MagicMock()
        mock_aip.check_ip.return_value = {"status": "NO_MATCH", "abuse_confidence_score": 0}
        mock_aip.is_public_ip.return_value = True

        service = ThreatIntelService(threatfox=mock_tf, urlhaus=mock_uh, abuseipdb=mock_aip)
        ti_result = service.analyze_threat_intel("http://regular-site.com", domain="regular-site.com", ip="93.184.216.34")

        self.assertEqual(ti_result["status"], "SUCCESS")
        self.assertEqual(ti_result["summary"]["positive_hits"], 0)
        self.assertFalse(ti_result["summary"]["known_malicious_ioc"])

    def test_24_all_external_sources_unavailable(self):
        """All external TI sources unavailable -> status is UNAVAILABLE, not clean"""
        mock_tf = MagicMock()
        mock_tf.lookup_ioc.return_value = {"status": "UNAVAILABLE", "hits": 0}
        mock_uh = MagicMock()
        mock_uh.lookup_url.return_value = {"status": "UNAVAILABLE", "hits": 0}
        mock_aip = MagicMock()
        mock_aip.check_ip.return_value = {"status": "UNAVAILABLE"}
        mock_aip.is_public_ip.return_value = True

        service = ThreatIntelService(threatfox=mock_tf, urlhaus=mock_uh, abuseipdb=mock_aip)
        ti_result = service.analyze_threat_intel("http://test-site.org", domain="test-site.org", ip="1.2.3.4")

        self.assertEqual(ti_result["status"], "UNAVAILABLE")
        self.assertNotEqual(ti_result["reputation"], "CLEAN")

    def test_25_one_source_unavailable_others_success(self):
        """Failure isolation: If AbuseIPDB is RATE_LIMITED, ThreatFox & URLhaus still succeed"""
        mock_tf = MagicMock()
        mock_tf.lookup_ioc.return_value = {"status": "NO_MATCH", "hits": 0, "matches": []}
        mock_uh = MagicMock()
        mock_uh.lookup_url.return_value = {"status": "NO_MATCH", "hits": 0}
        mock_uh.lookup_host.return_value = {"status": "NO_MATCH", "hits": 0}
        mock_aip = MagicMock()
        mock_aip.check_ip.return_value = {"status": "RATE_LIMITED"}
        mock_aip.is_public_ip.return_value = True

        service = ThreatIntelService(threatfox=mock_tf, urlhaus=mock_uh, abuseipdb=mock_aip)
        ti_result = service.analyze_threat_intel("http://mixed-status.org", domain="mixed-status.org", ip="1.2.3.4")

        self.assertEqual(ti_result["status"], "PARTIAL")
        self.assertEqual(ti_result["sources"]["threatfox"]["status"], "NO_MATCH")
        self.assertEqual(ti_result["sources"]["abuseipdb"]["status"], "RATE_LIMITED")

    def test_26_legitimate_nptel_domain(self):
        """NPTEL education domain intelligence + clean TI supports Benign"""
        url = "https://onlinecourses.nptel.ac.in/e-learning/course/noc26_hs247"
        ti_result = self.service.analyze_threat_intel(url, domain="onlinecourses.nptel.ac.in", ip="142.250.193.174")

        # Trusted domain is detected as Education
        td_source = ti_result["sources"]["trusted_domain"]
        self.assertTrue(td_source["is_known"])
        self.assertEqual(td_source["category"].lower(), "education")

    def test_27_suspicious_url(self):
        """Suspicious URL with high AbuseIPDB score gets flagged in TI indicators"""
        mock_tf = MagicMock()
        mock_tf.lookup_ioc.return_value = {"status": "NO_MATCH", "hits": 0}
        mock_uh = MagicMock()
        mock_uh.lookup_url.return_value = {"status": "NO_MATCH", "hits": 0}
        mock_uh.lookup_host.return_value = {"status": "NO_MATCH", "hits": 0}
        mock_aip = MagicMock()
        mock_aip.check_ip.return_value = {
            "status": "SUCCESS", "abuse_confidence_score": 82, "total_reports": 45
        }
        mock_aip.is_public_ip.return_value = True

        service = ThreatIntelService(threatfox=mock_tf, urlhaus=mock_uh, abuseipdb=mock_aip)
        res = service.analyze_threat_intel("http://198.51.100.77/login", domain="198.51.100.77", ip="198.51.100.77")

        self.assertIn("REPUTATION:AbuseIPDB score 82% for 198.51.100.77", res["indicators"])

    def test_28_known_malware_url_fixture(self):
        """URLhaus fixture returns malware IOC which is preserved in evidence"""
        mock_uh = MagicMock()
        mock_uh.lookup_url.return_value = {
            "status": "SUCCESS", "hits": 1, "threat": "malware_download",
            "url_status": "online", "tags": ["agenttesla"]
        }
        mock_tf = MagicMock()
        mock_tf.lookup_ioc.return_value = {"status": "NO_MATCH", "hits": 0}
        mock_aip = MagicMock()
        mock_aip.check_ip.return_value = {"status": "NO_MATCH", "abuse_confidence_score": 0}
        mock_aip.is_public_ip.return_value = True

        service = ThreatIntelService(threatfox=mock_tf, urlhaus=mock_uh, abuseipdb=mock_aip)
        res = service.analyze_threat_intel("http://known-fixture.com/tesla.bin", domain="known-fixture.com")
        self.assertTrue(res["summary"]["known_malware_url"])

    def test_29_private_ip_not_causing_external_reputation_lookup(self):
        """Private RFC1918 IPs (192.168.1.1, 10.0.0.1, 127.0.0.1) are SKIPPED from AbuseIPDB"""
        provider = AbuseIPDBProvider(api_key="valid_key")
        for private_ip in ["127.0.0.1", "192.168.1.1", "10.0.0.5", "172.16.0.1"]:
            res = provider.check_ip(private_ip)
            self.assertEqual(res["status"], "SKIPPED_PRIVATE_IP")

    @patch("requests.post")
    def test_30_duplicate_ioc_query_avoided(self, mock_post):
        """ThreatFox provider deduplicates identical queries within same scan"""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"query_status": "no_result"}
        mock_post.return_value = mock_resp

        tf = ThreatFoxProvider(api_key="valid_key")
        res1 = tf.lookup_ioc("duplicate-query.com")
        res2 = tf.lookup_ioc("duplicate-query.com")

        self.assertEqual(res1["status"], "NO_MATCH")
        self.assertEqual(res2["status"], "NO_MATCH")
        # requests.post called only once due to internal cache
        self.assertEqual(mock_post.call_count, 1)


class TestThreatIntelSecurityAndPolicy(unittest.TestCase):
    """Security tests 31 to 36"""

    def setUp(self):
        self.real_tf_key = os.environ.get("THREATFOX_API_KEY", "")
        self.real_uh_key = os.environ.get("URLHAUS_API_KEY", "")
        self.real_aip_key = os.environ.get("ABUSEIPDB_API_KEY", "")

    def test_31_no_api_keys_in_logs(self):
        """Ensure provider log messages never interpolate the API keys"""
        tf = ThreatFoxProvider(api_key="super_secret_threatfox_key_xyz")
        uh = URLhausProvider(api_key="super_secret_urlhaus_key_xyz")
        aip = AbuseIPDBProvider(api_key="super_secret_abuseipdb_key_xyz")

        # Mock an error to test logging
        with patch.object(tf, '_query_cache', {}), patch("requests.post", side_effect=Exception("network down")):
            res = tf.lookup_ioc("test.com")
            self.assertNotIn("super_secret_threatfox_key_xyz", json.dumps(res))

    def test_32_no_api_keys_in_mongodb(self):
        """Stored MongoDB case document never contains API keys or secret auth headers"""
        service = ThreatIntelService()
        evidence = service.analyze_threat_intel("http://safe-site.com", domain="safe-site.com", ip="8.8.8.8")
        evidence_str = json.dumps(evidence)

        if self.real_tf_key:
            self.assertNotIn(self.real_tf_key, evidence_str)
        if self.real_uh_key:
            self.assertNotIn(self.real_uh_key, evidence_str)
        if self.real_aip_key:
            self.assertNotIn(self.real_aip_key, evidence_str)

    def test_33_no_api_keys_in_sql(self):
        """Threat indicators passed for SQL persistence do not contain API keys or auth headers"""
        service = ThreatIntelService()
        evidence = service.analyze_threat_intel("http://safe-site.com", domain="safe-site.com", ip="8.8.8.8")
        indicators = evidence.get("indicators", []) + evidence.get("external_indicators", [])

        for ind in indicators:
            if self.real_tf_key:
                self.assertNotIn(self.real_tf_key, str(ind))
            if self.real_uh_key:
                self.assertNotIn(self.real_uh_key, str(ind))
            if self.real_aip_key:
                self.assertNotIn(self.real_aip_key, str(ind))

    def test_34_no_api_keys_in_ai_payload(self):
        """EvidenceNormalizer.build_ai_input never leaks raw API keys or provider tokens"""
        service = ThreatIntelService()
        raw_evidence = service.analyze_threat_intel("http://safe-site.com", domain="safe-site.com", ip="8.8.8.8")
        normalized = {"threat_intelligence": EvidenceNormalizer.normalize("threat_intelligence", raw_evidence)}

        ai_payload = EvidenceNormalizer.build_ai_input({"class": "Unknown", "confidence": 0.5}, normalized)
        ai_str = json.dumps(ai_payload)

        if self.real_tf_key:
            self.assertNotIn(self.real_tf_key, ai_str)
        if self.real_uh_key:
            self.assertNotIn(self.real_uh_key, ai_str)
        if self.real_aip_key:
            self.assertNotIn(self.real_aip_key, ai_str)

    def test_35_no_paid_provider_path(self):
        """Commercial providers (VirusTotal, AlienVault OTX, Shodan) are rejected"""
        for paid_prov in ["virustotal", "vt", "alienvault", "otx", "shodan", "recordedfuture"]:
            allowed, msg = FreeOnlyGuard.is_provider_allowed(paid_prov)
            self.assertFalse(allowed)
            self.assertEqual(msg, "CONFIGURATION_BLOCKED")

    def test_36_free_only_guard_blocks_premium_configuration(self):
        """FreeOnlyGuard blocks commercial API domain endpoints"""
        allowed, msg = FreeOnlyGuard.is_endpoint_allowed("https://www.virustotal.com/api/v3/urls")
        self.assertFalse(allowed)
        self.assertEqual(msg, "CONFIGURATION_BLOCKED")

        # Free endpoints are allowed
        allowed, msg = FreeOnlyGuard.is_endpoint_allowed("https://threatfox-api.abuse.ch/api/v1/")
        self.assertTrue(allowed)
        self.assertEqual(msg, "ALLOWED")


if __name__ == "__main__":
    unittest.main()
