"""
Free-Only Provider Guard for Threat Intelligence.
Strictly enforces zero-cost / community / standard-free tiers.
Blocks any accidental or intentional commercial / premium endpoints.
"""
import os
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Allowed free / community providers
ALLOWED_TI_PROVIDERS = {
    "threatfox",
    "threatfox_community",
    "urlhaus",
    "urlhaus_community",
    "abuseipdb",
    "abuseipdb_standard",
    "local_sql",
    "trusted_domain",
}

# Explicitly blocked commercial / premium providers
BLOCKED_PAID_PROVIDERS = {
    "virustotal",
    "vt",
    "alienvault",
    "otx",
    "alienvault_otx",
    "shodan",
    "recordedfuture",
    "crowdstrike",
    "mandiant",
    "ipqualityscore",
    "censys",
    "securitytrails",
}

# Allowed API endpoint domains
ALLOWED_API_DOMAINS = {
    "threatfox-api.abuse.ch",
    "urlhaus-api.abuse.ch",
    "api.abuseipdb.com",
}


class FreeOnlyGuard:
    """
    Enforces the FREE_ONLY policy across the Threat Intelligence subsystem.
    """

    @classmethod
    def is_free_only(cls) -> bool:
        """Check if FREE_ONLY mode is active (default True)."""
        val = os.environ.get("FREE_ONLY", "true").lower()
        return val in ("true", "1", "yes")

    @classmethod
    def allow_paid_providers(cls) -> bool:
        """Check if paid providers are allowed (hardcoded policy default False)."""
        val = os.environ.get("ALLOW_PAID_PROVIDERS", "false").lower()
        return val in ("true", "1", "yes")

    @classmethod
    def is_provider_allowed(cls, provider_name: str) -> tuple[bool, str]:
        """
        Verify whether a provider is allowed under the Free-Only policy.

        Args:
            provider_name: Normalized provider identifier (e.g. 'threatfox')

        Returns:
            tuple (allowed: bool, status_message: str)
        """
        if not provider_name:
            return False, "UNKNOWN_PROVIDER"

        p_name = provider_name.strip().lower()

        # Check explicit blocklist first
        if p_name in BLOCKED_PAID_PROVIDERS:
            logger.warning(
                f"[FREE-ONLY GUARD] Provider '{p_name}' is a commercial/paid service and is BLOCKED."
            )
            return False, "CONFIGURATION_BLOCKED"

        if cls.is_free_only() and not cls.allow_paid_providers():
            if p_name in ALLOWED_TI_PROVIDERS:
                return True, "ALLOWED"
            else:
                logger.warning(
                    f"[FREE-ONLY GUARD] Provider '{p_name}' is not in free-only whitelist. BLOCKED."
                )
                return False, "CONFIGURATION_BLOCKED"

        return True, "ALLOWED"

    @classmethod
    def is_endpoint_allowed(cls, endpoint_url: str) -> tuple[bool, str]:
        """
        Verify whether an outbound HTTP endpoint domain is allowed.

        Args:
            endpoint_url: str target API URL

        Returns:
            tuple (allowed: bool, status_message: str)
        """
        if not cls.is_free_only():
            return True, "ALLOWED"

        try:
            parsed = urlparse(endpoint_url)
            host = (parsed.hostname or "").lower()
            if host in ALLOWED_API_DOMAINS:
                return True, "ALLOWED"
            else:
                logger.warning(
                    f"[FREE-ONLY GUARD] Endpoint host '{host}' is not in allowed free domains. BLOCKED."
                )
                return False, "CONFIGURATION_BLOCKED"
        except Exception as e:
            logger.error(f"[FREE-ONLY GUARD] Failed to parse endpoint URL: {e}")
            return False, "CONFIGURATION_BLOCKED"
