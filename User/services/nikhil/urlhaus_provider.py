"""
URLhaus Community API Provider for Nikhil Fallback.
Free-only threat intelligence for malware URL and host distribution lookup (abuse.ch).
"""
import os
import logging
import requests
from urllib.parse import urlparse
from User.services.nikhil.free_only_guard import FreeOnlyGuard

logger = logging.getLogger(__name__)

URLHAUS_URL_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"
URLHAUS_HOST_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/host/"
DEFAULT_TIMEOUT = 5.0


class URLhausProvider:
    """
    Queries the official abuse.ch URLhaus Community API for malware distribution URLs and hosts.
    Free under fair-use principles.
    """

    def __init__(self, api_key=None, timeout=DEFAULT_TIMEOUT):
        # Allow fallback to THREATFOX_API_KEY as both are abuse.ch Auth-Keys
        if api_key is not None:
            self.api_key = api_key
        else:
            self.api_key = os.environ.get("URLHAUS_API_KEY") or os.environ.get("THREATFOX_API_KEY")
        self.timeout = timeout
        self._query_cache = {}

    def is_enabled(self) -> bool:
        """Check if URLhaus is configured and allowed."""
        allowed, msg = FreeOnlyGuard.is_provider_allowed("urlhaus")
        if not allowed:
            logger.warning(f"URLhaus provider blocked by FreeOnlyGuard: {msg}")
            return False
        return bool(self.api_key and self.api_key.strip())

    def lookup_url(self, target_url: str) -> dict:
        """
        Check if target URL is known in URLhaus as malware distribution infrastructure.

        Args:
            target_url: str full URL

        Returns:
            dict normalized result
        """
        if not target_url or not isinstance(target_url, str):
            return self._format_result("ERROR", target_url, "Invalid URL provided")

        target_url = target_url.strip()
        cache_key = f"url:{target_url}"
        if cache_key in self._query_cache:
            return self._query_cache[cache_key]

        allowed, msg = FreeOnlyGuard.is_provider_allowed("urlhaus")
        if not allowed:
            res = self._format_result("CONFIGURATION_BLOCKED", target_url, "URLhaus blocked by FreeOnlyGuard")
            self._query_cache[cache_key] = res
            return res

        if not self.api_key or not self.api_key.strip():
            res = self._format_result("UNAVAILABLE", target_url, "URLhaus API key not configured")
            self._query_cache[cache_key] = res
            return res

        headers = {
            "Auth-Key": self.api_key.strip(),
            "User-Agent": "Nikhil-Fallback/1.0"
        }
        data = {"url": target_url}

        try:
            response = requests.post(
                URLHAUS_URL_ENDPOINT,
                headers=headers,
                data=data,
                timeout=self.timeout
            )
            res = self._parse_response(response, target_url, is_url_query=True)
            self._query_cache[cache_key] = res
            return res

        except requests.exceptions.Timeout:
            logger.warning(f"URLhaus URL request timed out ({self.timeout}s) for '{target_url}'")
            res = self._format_result("TIMEOUT", target_url, f"URLhaus request timed out after {self.timeout}s")
            self._query_cache[cache_key] = res
            return res
        except requests.exceptions.RequestException as e:
            logger.warning(f"URLhaus URL request network error: {e}")
            res = self._format_result("UNAVAILABLE", target_url, f"URLhaus network unavailable: {type(e).__name__}")
            self._query_cache[cache_key] = res
            return res
        except Exception as e:
            logger.error(f"URLhaus URL request unexpected error: {e}")
            res = self._format_result("ERROR", target_url, f"URLhaus unexpected error: {str(e)}")
            self._query_cache[cache_key] = res
            return res

    def lookup_host(self, host: str) -> dict:
        """
        Check if host/domain is known in URLhaus as malware distribution host.

        Args:
            host: str domain or IP

        Returns:
            dict normalized result
        """
        if not host or not isinstance(host, str):
            return self._format_result("ERROR", host, "Invalid host provided")

        host = host.strip()
        cache_key = f"host:{host}"
        if cache_key in self._query_cache:
            return self._query_cache[cache_key]

        allowed, msg = FreeOnlyGuard.is_provider_allowed("urlhaus")
        if not allowed:
            res = self._format_result("CONFIGURATION_BLOCKED", host, "URLhaus blocked by FreeOnlyGuard")
            self._query_cache[cache_key] = res
            return res

        if not self.api_key or not self.api_key.strip():
            res = self._format_result("UNAVAILABLE", host, "URLhaus API key not configured")
            self._query_cache[cache_key] = res
            return res

        headers = {
            "Auth-Key": self.api_key.strip(),
            "User-Agent": "Nikhil-Fallback/1.0"
        }
        data = {"host": host}

        try:
            response = requests.post(
                URLHAUS_HOST_ENDPOINT,
                headers=headers,
                data=data,
                timeout=self.timeout
            )
            res = self._parse_response(response, host, is_url_query=False)
            self._query_cache[cache_key] = res
            return res

        except requests.exceptions.Timeout:
            logger.warning(f"URLhaus host request timed out ({self.timeout}s) for '{host}'")
            res = self._format_result("TIMEOUT", host, f"URLhaus host query timed out after {self.timeout}s")
            self._query_cache[cache_key] = res
            return res
        except requests.exceptions.RequestException as e:
            logger.warning(f"URLhaus host request network error: {e}")
            res = self._format_result("UNAVAILABLE", host, f"URLhaus network unavailable: {type(e).__name__}")
            self._query_cache[cache_key] = res
            return res
        except Exception as e:
            logger.error(f"URLhaus host request unexpected error: {e}")
            res = self._format_result("ERROR", host, f"URLhaus host query error: {str(e)}")
            self._query_cache[cache_key] = res
            return res

    def _parse_response(self, response, query_term: str, is_url_query: bool) -> dict:
        if response.status_code == 429:
            logger.warning("URLhaus API rate limit reached (HTTP 429)")
            return self._format_result("RATE_LIMITED", query_term, "URLhaus API rate limited (HTTP 429)")

        if response.status_code in (401, 403):
            logger.warning("URLhaus API authentication failure")
            return self._format_result("AUTH_ERROR", query_term, "URLhaus authentication failed (invalid key)")

        if response.status_code >= 500:
            logger.warning(f"URLhaus server error: HTTP {response.status_code}")
            return self._format_result("UNAVAILABLE", query_term, f"URLhaus server unavailable (HTTP {response.status_code})")

        try:
            data = response.json()
        except Exception as e:
            logger.warning(f"URLhaus malformed JSON: {e}")
            return self._format_result("ERROR", query_term, "Malformed JSON from URLhaus")

        query_status = data.get("query_status")

        if query_status == "ok":
            # Match found
            payloads = data.get("payloads") or []
            urls = data.get("urls") or []
            url_count = data.get("url_count") or (1 if is_url_query else len(urls))

            tags = data.get("tags") or []
            threat = data.get("threat")
            url_status = data.get("url_status")
            date_added = data.get("date_added")

            res = {
                "status": "SUCCESS",
                "provider": "URLhaus",
                "query_term": query_term,
                "hits": 1 if is_url_query else max(1, len(urls)),
                "threat": threat,
                "url_status": url_status,
                "tags": tags,
                "date_added": date_added,
                "payload_count": len(payloads),
                "url_count": url_count,
                "reporter": data.get("reporter"),
                "message": f"Malware infrastructure found in URLhaus (threat: {threat or 'malware'}, status: {url_status or 'active'})"
            }
            return res

        elif query_status in ("no_results", "not_found"):
            return self._format_result("NO_MATCH", query_term, "No matching malware record in URLhaus")
        elif query_status == "invalid_api_key":
            return self._format_result("AUTH_ERROR", query_term, "URLhaus returned invalid_api_key")
        else:
            return self._format_result("NO_MATCH", query_term, f"URLhaus query status: {query_status}")

    def _format_result(self, status: str, term: str, message: str) -> dict:
        return {
            "status": status,
            "provider": "URLhaus",
            "query_term": term,
            "hits": 0,
            "threat": None,
            "url_status": None,
            "tags": [],
            "date_added": None,
            "payload_count": 0,
            "message": message
        }
