"""
AI Provider Manager — Failover Controller.
Manages the provider chain: Gemini Free -> OpenRouter Free -> Local Deterministic.
"""
import os
import time
import logging

from User.services.nikhil.ai_provider_base import is_free_only_mode

logger = logging.getLogger(__name__)

# Statuses that trigger failover to next provider
FAILOVER_STATUSES = {
    "UNAVAILABLE", "RATE_LIMITED", "QUOTA_EXCEEDED",
    "TIMEOUT", "ERROR", "BLOCKED", "INVALID_RESPONSE"
}


class AIProviderManager:
    """
    Manages AI provider selection and failover.

    Default order:
        1. Gemini Free
        2. OpenRouter Free
        3. Local deterministic (no AI)

    Constraints:
        - Maximum 2 provider attempts per scan
        - No paid providers when FREE_ONLY=true
        - No infinite retries
        - Records all attempt metadata
    """

    MAX_PROVIDER_ATTEMPTS = int(os.environ.get('AI_MAX_PROVIDER_ATTEMPTS', '2'))

    def __init__(self):
        self.providers = []
        self._initialize_providers()
        self.attempt_log = []

    def _initialize_providers(self):
        """Initialize the ordered provider chain."""
        # Provider 1: Gemini
        try:
            from User.services.nikhil.gemini_provider import GeminiProvider
            gemini = GeminiProvider()
            if gemini.is_configured():
                self.providers.append(gemini)
                logger.info(f"Gemini provider initialized: model={gemini.model}")
            else:
                logger.info("Gemini provider not configured (disabled or no API key)")
        except Exception as e:
            logger.warning(f"Failed to initialize Gemini provider: {e}")

        # Provider 2: OpenRouter
        try:
            from User.services.nikhil.openrouter_provider import OpenRouterProvider
            openrouter = OpenRouterProvider()
            if openrouter.is_configured():
                self.providers.append(openrouter)
                logger.info(f"OpenRouter provider initialized: model={openrouter.model}")
            else:
                logger.info("OpenRouter provider not configured (disabled or no API key)")
        except Exception as e:
            logger.warning(f"Failed to initialize OpenRouter provider: {e}")

    def analyze_with_failover(self, evidence_payload):
        """
        Attempt AI analysis with failover through the provider chain.

        Args:
            evidence_payload: dict of normalized evidence for AI

        Returns:
            dict: {
                "status": str,
                "provider": str or None,
                "model": str or None,
                "ai_required": True,
                "ai_called": bool,
                "result": dict or None,
                "provider_attempts": int,
                "attempt_log": list,
                "failover_reason": str or None,
                "total_latency_ms": int
            }
        """
        start_time = time.time()
        self.attempt_log = []
        attempts = 0
        last_failover_reason = None

        if not self.providers:
            return {
                "status": "UNAVAILABLE",
                "provider": None,
                "model": None,
                "ai_required": True,
                "ai_called": False,
                "result": None,
                "provider_attempts": 0,
                "attempt_log": [{"provider": "none", "status": "NO_PROVIDERS_CONFIGURED"}],
                "failover_reason": "No AI providers configured",
                "total_latency_ms": 0
            }

        for provider in self.providers:
            if attempts >= self.MAX_PROVIDER_ATTEMPTS:
                logger.info(f"Max provider attempts ({self.MAX_PROVIDER_ATTEMPTS}) reached")
                break

            # Check free-only policy
            if not provider.is_allowed():
                attempt_entry = {
                    "provider": provider.PROVIDER_NAME,
                    "model": provider.model,
                    "status": "BLOCKED",
                    "reason": "Blocked by free-only policy"
                }
                self.attempt_log.append(attempt_entry)
                last_failover_reason = f"{provider.PROVIDER_NAME}: blocked by policy"
                continue

            attempts += 1
            logger.info(f"Attempting AI analysis with {provider.PROVIDER_NAME} (attempt {attempts})")

            try:
                result = provider.analyze(evidence_payload)
            except Exception as e:
                result = provider._build_empty_result("ERROR", f"Unexpected error: {str(e)[:200]}")

            attempt_entry = {
                "provider": provider.PROVIDER_NAME,
                "model": provider.model,
                "status": result.get("status", "ERROR"),
                "latency_ms": result.get("latency_ms", 0)
            }
            if result.get("error"):
                attempt_entry["error"] = result["error"]
            self.attempt_log.append(attempt_entry)

            # Success case
            if result.get("status") == "SUCCESS":
                total_latency = int((time.time() - start_time) * 1000)
                logger.info(f"AI analysis succeeded with {provider.PROVIDER_NAME} in {total_latency}ms")
                return {
                    "status": "SUCCESS",
                    "provider": provider.PROVIDER_NAME,
                    "model": provider.model,
                    "ai_required": True,
                    "ai_called": True,
                    "result": result,
                    "provider_attempts": attempts,
                    "attempt_log": self.attempt_log,
                    "failover_reason": last_failover_reason,
                    "total_latency_ms": total_latency
                }

            # Failover case
            last_failover_reason = f"{provider.PROVIDER_NAME}: {result.get('status', 'FAILED')}"
            logger.info(f"Provider {provider.PROVIDER_NAME} failed: {result.get('status')} — trying next")

        # All providers failed
        total_latency = int((time.time() - start_time) * 1000)
        logger.warning(f"All AI providers failed after {attempts} attempts")
        return {
            "status": "UNAVAILABLE",
            "provider": None,
            "model": None,
            "ai_required": True,
            "ai_called": True,
            "result": None,
            "provider_attempts": attempts,
            "attempt_log": self.attempt_log,
            "failover_reason": last_failover_reason or "All providers failed",
            "total_latency_ms": total_latency
        }

    def get_provider_status(self):
        """Get current status of all configured providers."""
        status = {
            "free_only_mode": is_free_only_mode(),
            "max_attempts": self.MAX_PROVIDER_ATTEMPTS,
            "configured_providers": []
        }
        for p in self.providers:
            status["configured_providers"].append({
                "name": p.PROVIDER_NAME,
                "type": p.PROVIDER_TYPE,
                "enabled": p.enabled,
                "configured": p.is_configured(),
                "allowed": p.is_allowed(),
                "model": p.model
            })
        return status
