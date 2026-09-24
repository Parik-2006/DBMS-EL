"""
Gemini AI Provider — Free-only integration via Google Generative AI API.
"""
import os
import json
import time
import logging

from User.services.nikhil.ai_provider_base import AIProviderBase

logger = logging.getLogger(__name__)


class GeminiProvider(AIProviderBase):
    """
    Google Gemini AI provider with free-only enforcement.
    Uses the REST API directly via requests (no SDK dependency).
    """

    PROVIDER_NAME = "gemini"
    PROVIDER_TYPE = "free"  # Gemini has free-tier models

    GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"

    def __init__(self):
        super().__init__()
        self.enabled = os.environ.get('GEMINI_ENABLED', 'true').lower() in ('true', '1', 'yes')
        self.api_key = os.environ.get('GEMINI_API_KEY')
        self.model = os.environ.get('GEMINI_MODEL', 'gemini-2.5-flash')

    def analyze(self, evidence_payload):
        """
        Call Gemini API with normalized evidence.

        Returns structured result dict.
        """
        start_time = time.time()

        # Pre-flight checks
        if not self.enabled:
            return self._build_empty_result("UNAVAILABLE", "Gemini provider is disabled")

        if not self.api_key:
            return self._build_empty_result("UNAVAILABLE", "Gemini API key not configured")

        if not self.is_allowed():
            return self._build_empty_result("BLOCKED", "Gemini blocked by free-only policy")

        try:
            import requests

            url = self.GEMINI_API_URL.format(model=self.model)
            headers = {"Content-Type": "application/json"}
            params = {"key": self.api_key}

            system_prompt = self._build_system_prompt()
            user_content = json.dumps(evidence_payload, indent=2, default=str)

            # Enforce input size limit
            max_chars = int(os.environ.get('MAX_AI_TEXT_CHARS', '6000'))
            if len(user_content) > max_chars:
                user_content = user_content[:max_chars] + "\n... (truncated)"

            request_body = {
                "contents": [
                    {
                        "parts": [
                            {"text": f"{system_prompt}\n\nEvidence data:\n{user_content}"}
                        ]
                    }
                ],
                "generationConfig": {
                    "temperature": 0.1,
                    "maxOutputTokens": max(self.max_output_tokens, 2048),
                    "responseMimeType": "application/json",
                    "thinkingConfig": {"thinkingBudget": 0}
                }
            }

            response = requests.post(
                url,
                headers=headers,
                params=params,
                json=request_body,
                timeout=self.timeout
            )

            latency_ms = int((time.time() - start_time) * 1000)

            # Handle HTTP errors
            if response.status_code == 401:
                return self._build_empty_result("UNAVAILABLE", "Gemini: Invalid API key (401)", latency_ms)
            elif response.status_code == 403:
                return self._build_empty_result("UNAVAILABLE", "Gemini: Access forbidden (403)", latency_ms)
            elif response.status_code == 429:
                return self._build_empty_result("RATE_LIMITED", "Gemini: Rate limited (429)", latency_ms)
            elif response.status_code >= 500:
                return self._build_empty_result("ERROR", f"Gemini: Server error ({response.status_code})", latency_ms)
            elif response.status_code != 200:
                return self._build_empty_result("ERROR", f"Gemini: HTTP {response.status_code}", latency_ms)

            # Parse response
            resp_data = response.json()

            # Extract text from Gemini response
            candidates = resp_data.get("candidates", [])
            if not candidates:
                return self._build_empty_result("INVALID_RESPONSE", "Gemini: No candidates in response", latency_ms)

            content = candidates[0].get("content", {})
            parts = content.get("parts", [])
            if not parts:
                return self._build_empty_result("INVALID_RESPONSE", "Gemini: No parts in response", latency_ms)

            raw_text = parts[0].get("text", "")

            # Parse JSON from response
            return self._parse_ai_response(raw_text, latency_ms)

        except ImportError:
            return self._build_empty_result("UNAVAILABLE", "requests library not available")
        except Exception as e:
            latency_ms = int((time.time() - start_time) * 1000)
            error_str = str(e)
            # Check for timeout
            if "timeout" in error_str.lower() or "timed out" in error_str.lower():
                return self._build_empty_result("TIMEOUT", f"Gemini: Request timed out", latency_ms)
            # Check for quota
            if "quota" in error_str.lower() or "resource" in error_str.lower():
                return self._build_empty_result("QUOTA_EXCEEDED", f"Gemini: Quota exceeded", latency_ms)
            logger.error(f"Gemini provider error: {e}", exc_info=False)
            return self._build_empty_result("ERROR", f"Gemini: {error_str[:200]}", latency_ms)

    def _parse_ai_response(self, raw_text, latency_ms):
        """Parse and validate the AI response JSON."""
        try:
            # Try to extract JSON from the response
            text = raw_text.strip()

            # Remove markdown code fences if present
            if text.startswith("```"):
                lines = text.split("\n")
                text = "\n".join(lines[1:])
                if text.endswith("```"):
                    text = text[:-3]
                text = text.strip()

            parsed = json.loads(text)

            # Validate required fields
            valid_assessments = [
                "LIKELY_BENIGN", "LIKELY_PHISHING", "LIKELY_MALWARE",
                "LIKELY_DEFACEMENT", "CONFLICTING", "INCONCLUSIVE"
            ]

            assessment = parsed.get("assessment")
            if assessment not in valid_assessments:
                return self._build_empty_result(
                    "INVALID_RESPONSE",
                    f"Gemini: Invalid assessment '{assessment}'",
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
                f"Gemini: Response is not valid JSON",
                latency_ms
            )
