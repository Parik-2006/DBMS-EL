"""
AbuseIPDB Provider for Nikhil Fallback.
Free-only IP reputation intelligence (Standard free tier, up to 1,000 checks/day).
"""
import os
import ipaddress
import logging
import requests
from User.services.nikhil.free_only_guard import FreeOnlyGuard

logger = logging.getLogger(__name__)

ABUSEIPDB_CHECK_ENDPOINT = "https://api.abuseipdb.com/api/v2/check"
DEFAULT_TIMEOUT = 5.0


class AbuseIPDBProvider:
    """
    Queries AbuseIPDB API v2 check endpoint for public IP address reputation.
    Enforces free quota limits and skips private/local IP ranges.
    """

    def __init__(self, api_key=None, timeout=DEFAULT_TIMEOUT):
        self.api_key = api_key if api_key is not None else os.environ.get("ABUSEIPDB_API_KEY")
        self.timeout = timeout
        self._query_cache = {}

    def is_enabled(self) -> bool:
        """Check if AbuseIPDB is configured and allowed."""
        allowed, msg = FreeOnlyGuard.is_provider_allowed("abuseipdb")
        if not allowed:
            logger.warning(f"AbuseIPDB provider blocked by FreeOnlyGuard: {msg}")
            return False
        return bool(self.api_key and self.api_key.strip())

    @staticmethod
    def is_public_ip(ip_str: str) -> bool:
        """
        Check if an IP string is a valid public, routable IP address.
        Returns False for RFC1918 private IPs, loopback, link-local, and reserved ranges.
        """
        if not ip_str or not isinstance(ip_str, str):
            return False
        try:
            ip_obj = ipaddress.ip_address(ip_str.strip())
            if (ip_obj.is_private or ip_obj.is_loopback or 
                ip_obj.is_reserved or ip_obj.is_link_local or 
                ip_obj.is_multicast or ip_obj.is_unspecified):
                return False
            return True
        except ValueError:
            return False

    def check_ip(self, ip_address: str, max_age_days: int = 90) -> dict:
        """
        Check reputation of a single public IP address.

        Args:
            ip_address: str IPv4 or IPv6 address
            max_age_days: int max age of reports (default 90)

        Returns:
            dict normalized reputation data
        """
        if not ip_address or not isinstance(ip_address, str):
            return self._format_result("ERROR", ip_address, "Invalid IP address provided")

        ip_clean = ip_address.strip()

        # Deduplication
        if ip_clean in self._query_cache:
            return self._query_cache[ip_clean]

        # Guard private IP ranges: do NOT submit internal network info to public API
        if not self.is_public_ip(ip_clean):
            res = self._format_result(
                "SKIPPED_PRIVATE_IP",
                ip_clean,
                "Private, loopback, or non-routable IP address skipped from public reputation check"
            )
            self._query_cache[ip_clean] = res
            return res

        allowed, msg = FreeOnlyGuard.is_provider_allowed("abuseipdb")
        if not allowed:
            res = self._format_result("CONFIGURATION_BLOCKED", ip_clean, "AbuseIPDB blocked by FreeOnlyGuard")
            self._query_cache[ip_clean] = res
            return res

        if not self.api_key or not self.api_key.strip():
            res = self._format_result("UNAVAILABLE", ip_clean, "AbuseIPDB API key not configured")
            self._query_cache[ip_clean] = res
            return res

        headers = {
            "Key": self.api_key.strip(),
            "Accept": "application/json",
            "User-Agent": "Nikhil-Fallback/1.0"
        }
        params = {
            "ipAddress": ip_clean,
            "maxAgeInDays": max_age_days
        }

        try:
            response = requests.get(
                ABUSEIPDB_CHECK_ENDPOINT,
                headers=headers,
                params=params,
                timeout=self.timeout
            )

            if response.status_code == 429:
                logger.warning("AbuseIPDB rate limit/quota reached (HTTP 429)")
                res = self._format_result(
                    "RATE_LIMITED",
                    ip_clean,
                    "AbuseIPDB daily quota or rate limit exceeded (HTTP 429)"
                )
                self._query_cache[ip_clean] = res
                return res

            if response.status_code in (401, 403):
                logger.warning("AbuseIPDB authentication failure")
                res = self._format_result(
                    "AUTH_ERROR",
                    ip_clean,
                    "AbuseIPDB authentication failed (invalid API key)"
                )
                self._query_cache[ip_clean] = res
                return res

            if response.status_code >= 500:
                logger.warning(f"AbuseIPDB server error: HTTP {response.status_code}")
                res = self._format_result(
                    "UNAVAILABLE",
                    ip_clean,
                    f"AbuseIPDB server unavailable (HTTP {response.status_code})"
                )
                self._query_cache[ip_clean] = res
                return res

            try:
                json_data = response.json()
            except Exception as e:
                logger.warning(f"AbuseIPDB malformed JSON response: {e}")
                res = self._format_result("ERROR", ip_clean, "Malformed JSON from AbuseIPDB")
                self._query_cache[ip_clean] = res
                return res

            data = json_data.get("data", {})
            abuse_score = data.get("abuseConfidenceScore", 0)
            total_reports = data.get("totalReports", 0)
            distinct_users = data.get("numDistinctUsers", 0)
            last_reported = data.get("lastReportedAt")
            country_code = data.get("countryCode")
            usage_type = data.get("usageType")
            isp = data.get("isp")
            domain = data.get("domain")
            is_whitelisted = data.get("isWhitelisted", False)

            # Determine normalized status: SUCCESS (with score > 0) or CLEAN_RESULT / NO_MATCH
            status = "SUCCESS" if abuse_score > 0 or total_reports > 0 else "NO_MATCH"

            res = {
                "status": status,
                "provider": "AbuseIPDB",
                "ip": ip_clean,
                "abuse_confidence_score": abuse_score,
                "total_reports": total_reports,
                "num_distinct_users": distinct_users,
                "last_reported_at": last_reported,
                "country_code": country_code,
                "usage_type": usage_type,
                "isp": isp,
                "domain": domain,
                "is_whitelisted": is_whitelisted,
                "message": f"Abuse confidence: {abuse_score}% ({total_reports} reports)"
            }
            self._query_cache[ip_clean] = res
            return res

        except requests.exceptions.Timeout:
            logger.warning(f"AbuseIPDB request timed out ({self.timeout}s) for '{ip_clean}'")
            res = self._format_result("TIMEOUT", ip_clean, f"AbuseIPDB request timed out after {self.timeout}s")
            self._query_cache[ip_clean] = res
            return res
        except requests.exceptions.RequestException as e:
            logger.warning(f"AbuseIPDB request network error: {e}")
            res = self._format_result("UNAVAILABLE", ip_clean, f"AbuseIPDB network unavailable: {type(e).__name__}")
            self._query_cache[ip_clean] = res
            return res
        except Exception as e:
            logger.error(f"AbuseIPDB unexpected error: {e}")
            res = self._format_result("ERROR", ip_clean, f"AbuseIPDB unexpected error: {str(e)}")
            self._query_cache[ip_clean] = res
            return res

    def _format_result(self, status: str, ip: str, message: str) -> dict:
        return {
            "status": status,
            "provider": "AbuseIPDB",
            "ip": ip,
            "abuse_confidence_score": 0,
            "total_reports": 0,
            "num_distinct_users": 0,
            "last_reported_at": None,
            "country_code": None,
            "usage_type": None,
            "isp": None,
            "domain": None,
            "is_whitelisted": False,
            "message": message
        }
