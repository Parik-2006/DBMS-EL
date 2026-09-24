"""
ThreatFox Community API Provider for Nikhil Fallback.
Free-only threat intelligence for IOC correlation (abuse.ch).
"""
import os
import logging
import requests
from User.services.nikhil.free_only_guard import FreeOnlyGuard

logger = logging.getLogger(__name__)

THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"
DEFAULT_TIMEOUT = 5.0


class ThreatFoxProvider:
    """
    Queries the official abuse.ch ThreatFox Community API for known IOCs.
    Free under fair-use principles.
    """

    def __init__(self, api_key=None, timeout=DEFAULT_TIMEOUT):
        self.api_key = api_key if api_key is not None else os.environ.get("THREATFOX_API_KEY")
        self.timeout = timeout
        self._query_cache = {}

    def is_enabled(self) -> bool:
        """Check if ThreatFox is configured and allowed."""
        allowed, msg = FreeOnlyGuard.is_provider_allowed("threatfox")
        if not allowed:
            logger.warning(f"ThreatFox provider blocked by FreeOnlyGuard: {msg}")
            return False
        return bool(self.api_key and self.api_key.strip())

    def lookup_ioc(self, search_term: str, exact_match: bool = True) -> dict:
        """
        Query ThreatFox for an exact IOC (domain, IP, URL).

        Args:
            search_term: str indicator value (domain, IP, etc.)
            exact_match: bool whether to enforce exact IOC match

        Returns:
            dict: {
                "status": "SUCCESS" | "NO_MATCH" | "UNAVAILABLE" | "RATE_LIMITED" | "AUTH_ERROR" | "TIMEOUT" | "ERROR" | "CONFIGURATION_BLOCKED",
                "provider": "ThreatFox",
                "search_term": search_term,
                "hits": int,
                "matches": list,
                "threat_types": list,
                "malware_families": list,
                "message": str
            }
        """
        if not search_term or not isinstance(search_term, str):
            return {
                "status": "ERROR",
                "provider": "ThreatFox",
                "search_term": search_term,
                "hits": 0,
                "matches": [],
                "threat_types": [],
                "malware_families": [],
                "message": "Invalid search term"
            }

        search_term = search_term.strip()

        # Deduplication check
        if search_term in self._query_cache:
            return self._query_cache[search_term]

        allowed, msg = FreeOnlyGuard.is_provider_allowed("threatfox")
        if not allowed:
            res = {
                "status": "CONFIGURATION_BLOCKED",
                "provider": "ThreatFox",
                "search_term": search_term,
                "hits": 0,
                "matches": [],
                "threat_types": [],
                "malware_families": [],
                "message": "ThreatFox blocked under current policy configuration"
            }
            self._query_cache[search_term] = res
            return res

        if not self.api_key or not self.api_key.strip():
            res = {
                "status": "UNAVAILABLE",
                "provider": "ThreatFox",
                "search_term": search_term,
                "hits": 0,
                "matches": [],
                "threat_types": [],
                "malware_families": [],
                "message": "ThreatFox API key not configured"
            }
            self._query_cache[search_term] = res
            return res

        headers = {
            "Auth-Key": self.api_key.strip(),
            "User-Agent": "Nikhil-Fallback/1.0",
            "Content-Type": "application/json"
        }
        payload = {
            "query": "search_ioc",
            "search_term": search_term,
            "exact_match": exact_match
        }

        try:
            response = requests.post(
                THREATFOX_API_URL,
                headers=headers,
                json=payload,
                timeout=self.timeout
            )

            # HTTP Status Code Handling
            if response.status_code == 429:
                logger.warning("ThreatFox API rate limit reached (HTTP 429)")
                res = {
                    "status": "RATE_LIMITED",
                    "provider": "ThreatFox",
                    "search_term": search_term,
                    "hits": 0,
                    "matches": [],
                    "threat_types": [],
                    "malware_families": [],
                    "message": "ThreatFox API rate limited (HTTP 429)"
                }
                self._query_cache[search_term] = res
                return res

            if response.status_code in (401, 403):
                logger.warning("ThreatFox API authentication failure")
                res = {
                    "status": "AUTH_ERROR",
                    "provider": "ThreatFox",
                    "search_term": search_term,
                    "hits": 0,
                    "matches": [],
                    "threat_types": [],
                    "malware_families": [],
                    "message": "ThreatFox authentication failed (invalid key)"
                }
                self._query_cache[search_term] = res
                return res

            if response.status_code >= 500:
                logger.warning(f"ThreatFox API server error: HTTP {response.status_code}")
                res = {
                    "status": "UNAVAILABLE",
                    "provider": "ThreatFox",
                    "search_term": search_term,
                    "hits": 0,
                    "matches": [],
                    "threat_types": [],
                    "malware_families": [],
                    "message": f"ThreatFox server unavailable (HTTP {response.status_code})"
                }
                self._query_cache[search_term] = res
                return res

            # Parse JSON body
            try:
                data = response.json()
            except Exception as e:
                logger.warning(f"ThreatFox malformed JSON response: {e}")
                res = {
                    "status": "ERROR",
                    "provider": "ThreatFox",
                    "search_term": search_term,
                    "hits": 0,
                    "matches": [],
                    "threat_types": [],
                    "malware_families": [],
                    "message": "Malformed JSON response from ThreatFox"
                }
                self._query_cache[search_term] = res
                return res

            query_status = data.get("query_status")

            if query_status == "ok":
                raw_items = data.get("data", [])
                normalized_matches = []
                threat_types = set()
                malware_families = set()

                for item in raw_items:
                    ioc_val = item.get("ioc")
                    t_type = item.get("threat_type")
                    t_desc = item.get("threat_type_desc")
                    malware = item.get("malware_printable")
                    conf = item.get("confidence_level")
                    first_seen = item.get("first_seen_utc")
                    last_seen = item.get("last_seen_utc")

                    if t_type:
                        threat_types.add(t_type)
                    if malware:
                        malware_families.add(malware)

                    normalized_matches.append({
                        "ioc": ioc_val,
                        "ioc_type": item.get("ioc_type"),
                        "threat_type": t_type,
                        "threat_type_desc": t_desc,
                        "malware_printable": malware,
                        "confidence_level": conf,
                        "first_seen_utc": first_seen,
                        "last_seen_utc": last_seen,
                        "tags": item.get("tags") or []
                    })

                res = {
                    "status": "SUCCESS",
                    "provider": "ThreatFox",
                    "search_term": search_term,
                    "hits": len(normalized_matches),
                    "matches": normalized_matches[:10],  # bounded
                    "threat_types": list(threat_types),
                    "malware_families": list(malware_families),
                    "message": f"Found {len(normalized_matches)} matching IOCs in ThreatFox"
                }
                self._query_cache[search_term] = res
                return res

            elif query_status == "no_result":
                res = {
                    "status": "NO_MATCH",
                    "provider": "ThreatFox",
                    "search_term": search_term,
                    "hits": 0,
                    "matches": [],
                    "threat_types": [],
                    "malware_families": [],
                    "message": "No matching IOC returned by ThreatFox"
                }
                self._query_cache[search_term] = res
                return res

            elif query_status == "invalid_api_key":
                res = {
                    "status": "AUTH_ERROR",
                    "provider": "ThreatFox",
                    "search_term": search_term,
                    "hits": 0,
                    "matches": [],
                    "threat_types": [],
                    "malware_families": [],
                    "message": "ThreatFox returned invalid_api_key"
                }
                self._query_cache[search_term] = res
                return res

            else:
                # Other status such as illegal_search_term
                res = {
                    "status": "NO_MATCH",
                    "provider": "ThreatFox",
                    "search_term": search_term,
                    "hits": 0,
                    "matches": [],
                    "threat_types": [],
                    "malware_families": [],
                    "message": f"ThreatFox query status: {query_status}"
                }
                self._query_cache[search_term] = res
                return res

        except requests.exceptions.Timeout:
            logger.warning(f"ThreatFox request timeout ({self.timeout}s) for '{search_term}'")
            res = {
                "status": "TIMEOUT",
                "provider": "ThreatFox",
                "search_term": search_term,
                "hits": 0,
                "matches": [],
                "threat_types": [],
                "malware_families": [],
                "message": f"ThreatFox request timed out after {self.timeout}s"
            }
            self._query_cache[search_term] = res
            return res

        except requests.exceptions.RequestException as e:
            logger.warning(f"ThreatFox request network exception: {e}")
            res = {
                "status": "UNAVAILABLE",
                "provider": "ThreatFox",
                "search_term": search_term,
                "hits": 0,
                "matches": [],
                "threat_types": [],
                "malware_families": [],
                "message": f"ThreatFox network unavailable: {type(e).__name__}"
            }
            self._query_cache[search_term] = res
            return res

        except Exception as e:
            logger.error(f"ThreatFox unexpected exception: {e}")
            res = {
                "status": "ERROR",
                "provider": "ThreatFox",
                "search_term": search_term,
                "hits": 0,
                "matches": [],
                "threat_types": [],
                "malware_families": [],
                "message": f"ThreatFox unexpected error: {str(e)}"
            }
            self._query_cache[search_term] = res
            return res
