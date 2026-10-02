"""
OpenRouter AI Provider — Free-only backup provider.
Uses OpenRouter's API to access free models only.
"""
import os
import json
import time
import logging

from User.services.nikhil.ai_provider_base import AIProviderBase

logger = logging.getLogger(__name__)


class OpenRouterProvider(AIProviderBase):
    """
    OpenRouter AI provider restricted to free models only.
    Acts as backup when Gemini is unavailable.
    """

    PROVIDER_NAME = "openrouter"
    PROVIDER_TYPE = "free"

    OPENROUTER_API_URL = "https://openrouter.ai/api/v1/chat/completions"

    def __init__(self):
        super().__init__()
        self.enabled = os.environ.get('OPENROUTER_ENABLED', 'false').lower() in ('true', '1', 'yes')
        self.api_key = os.environ.get('OPENROUTER_API_KEY')
        self.model = os.environ.get('OPENROUTER_MODEL', 'liquid/lfm-2.5-2.6b:free')

    def _validate_free_model(self):
        """Validate that the configured model is explicitly free."""
        if not self.model:
            return False
        # OpenRouter free models typically have ':free' suffix or are known free models
        known_free_patterns = [':free', 'llama-3.1-8b-instruct:free', 'mistral-7b-instruct:free']
        model_lower = self.model.lower()
        return any(pattern in model_lower for pattern in known_free_patterns)

    def analyze(self, evidence_payload):
        """
        Call OpenRouter API with normalized evidence.

        Returns structured result dict.
        """
        start_time = time.time()

        # Pre-flight checks
        if not self.enabled:
            return self._build_empty_result("UNAVAILABLE", "OpenRouter provider is disabled")

        if not self.api_key:
            return self._build_empty_result("UNAVAILABLE", "OpenRouter API key not configured")

        if not self.is_allowed():
            return self._build_empty_result("BLOCKED", "OpenRouter blocked by free-only policy")

        if not self._validate_free_model():
            return self._build_empty_result(
                "BLOCKED",
                f"OpenRouter model '{self.model}' is not validated as free — blocked by policy"
            )

        try:
            import requests

            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
                "HTTP-Referer": "https://pari-nikhil-security.local",
                "X-Title": "PARI-Nikhil URL Security Scanner"
            }

            system_prompt = self._build_system_prompt()
            user_content = json.dumps(evidence_payload, indent=2, default=str)

            # Enforce input size limit
            max_chars = int(os.environ.get('MAX_AI_TEXT_CHARS', '6000'))
            if len(user_content) > max_chars:
                user_content = user_content[:max_chars] + "\n... (truncated)"

            request_body = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": f"Analyze this URL evidence:\n{user_content}"}
                ],
                "temperature": 0.1,
                "max_tokens": self.max_output_tokens,
                "response_format": {"type": "json_object"}
            }

            response = requests.post(
                self.OPENROUTER_API_URL,
                headers=headers,
                json=request_body,
                timeout=self.timeout
            )

            latency_ms = int((time.time() - start_time) * 1000)

            # Handle HTTP errors
            if response.status_code == 401:
                return self._build_empty_result("UNAVAILABLE", "OpenRouter: Invalid API key (401)", latency_ms)
            elif response.status_code == 403:
                return self._build_empty_result("UNAVAILABLE", "OpenRouter: Access forbidden (403)", latency_ms)
            elif response.status_code == 429:
                return self._build_empty_result("RATE_LIMITED", "OpenRouter: Rate limited (429)", latency_ms)
            elif response.status_code >= 500:
                return self._build_empty_result("ERROR", f"OpenRouter: Server error ({response.status_code})", latency_ms)
            elif response.status_code != 200:
                return self._build_empty_result("ERROR", f"OpenRouter: HTTP {response.status_code}", latency_ms)

            # Parse response
            resp_data = response.json()

            choices = resp_data.get("choices", [])
            if not choices:
                return self._build_empty_result("INVALID_RESPONSE", "OpenRouter: No choices in response", latency_ms)

            message = choices[0].get("message", {})
            raw_text = message.get("content", "")

            return self._parse_ai_response(raw_text, latency_ms)

        except ImportError:
            return self._build_empty_result("UNAVAILABLE", "requests library not available")
        except Exception as e:
            latency_ms = int((time.time() - start_time) * 1000)
            error_str = str(e)
            if "timeout" in error_str.lower() or "timed out" in error_str.lower():
                return self._build_empty_result("TIMEOUT", "OpenRouter: Request timed out", latency_ms)
            logger.error(f"OpenRouter provider error: {e}", exc_info=False)
            return self._build_empty_result("ERROR", f"OpenRouter: {error_str[:200]}", latency_ms)

    def _parse_ai_response(self, raw_text, latency_ms):
        """Parse and validate the AI response JSON."""
        try:
            text = raw_text.strip()
            if text.startswith("```"):
                lines = text.split("\n")
                text = "\n".join(lines[1:])
                if text.endswith("```"):
                    text = text[:-3]
                text = text.strip()

            parsed = json.loads(text)

            valid_assessments = [
                "LIKELY_BENIGN", "LIKELY_PHISHING", "LIKELY_MALWARE",
                "LIKELY_DEFACEMENT", "CONFLICTING", "INCONCLUSIVE"
            ]

            assessment = parsed.get("assessment")
            if assessment not in valid_assessments:
                return self._build_empty_result(
                    "INVALID_RESPONSE",
                    f"OpenRouter: Invalid assessment '{assessment}'",
                    latency_ms
                )

            confidence = parsed.get("confidence", 0.0)
            try:
                confidence = float(confidence)
                confidence = max(0.0, min(1.0, confidence))
            except (ValueError, TypeError):
                confidence = 0.0

            return {
                "status": "SUCCESS",
                "provider": self.PROVIDER_NAME,
                "model": self.model,
                "assessment": assessment,
                "confidence": confidence,
                "supporting_evidence": parsed.get("supporting_evidence", [])[:10],
                "contradictory_evidence": parsed.get("contradictory_evidence", [])[:10],
                "observations": parsed.get("observations", [])[:10],
                "reasoning_summary": str(parsed.get("reasoning_summary", ""))[:500],
                "limitations": parsed.get("limitations", [])[:5],
                "error": None,
                "latency_ms": latency_ms
            }

        except json.JSONDecodeError:
            return self._build_empty_result(
                "INVALID_RESPONSE",
                "OpenRouter: Response is not valid JSON",
                latency_ms
            )
