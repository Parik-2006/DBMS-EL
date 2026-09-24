"""
AI Analysis Module — Real Provider Integration.
Uses AIGatekeeper to decide if AI is needed,
then AIProviderManager for free-only failover.
AI is an OPTIONAL evidence analyst — NOT the final authority.
"""
import os
import time
import logging

logger = logging.getLogger(__name__)


class AIAnalyzer:
    """
    AI / LLM Analysis Interface.

    IMPORTANT:
    - AI is OPTIONAL — the scan succeeds without it.
    - AI is an evidence analyst, NOT the final classifier.
    - The orchestrator (deterministic code) controls the workflow.
    - AI output is validated and bounded.
    - At most 1 successful AI call + 1 failover attempt per scan.
    """

    def __init__(self):
        self._provider_manager = None
        self._gatekeeper = None

    def _get_provider_manager(self):
        if self._provider_manager is None:
            from User.services.nikhil.ai_provider_manager import AIProviderManager
            self._provider_manager = AIProviderManager()
        return self._provider_manager

    def _get_gatekeeper(self):
        if self._gatekeeper is None:
            from User.services.nikhil.ai_gatekeeper import AIGatekeeper
            self._gatekeeper = AIGatekeeper()
        return self._gatekeeper

    def analyze_with_ai(self, evidence_data, initial_prediction=None, initial_confidence=None):
        """
        Perform AI analysis if warranted by the gatekeeper.

        Args:
            evidence_data: dict containing gathered evidence from all collectors
            initial_prediction: str initial ML class
            initial_confidence: float initial ML confidence

        Returns:
            dict: AI analysis result including gatekeeper decision and provider status
        """
        ai_enabled = os.environ.get('AI_ENABLED', 'true').lower() in ('true', '1', 'yes')

        # Check if AI is globally disabled
        if not ai_enabled:
            return {
                "status": "NOT_RUN",
                "ai_required": False,
                "ai_called": False,
                "provider": None,
                "model": None,
                "gatekeeper": {
                    "ai_required": False,
                    "reason": "AI globally disabled (AI_ENABLED=false)",
                    "priority": "LOW",
                    "triggers": []
                },
                "assessment": None,
                "confidence": 0.0,
                "supporting_evidence": [],
                "contradictory_evidence": [],
                "observations": [],
                "reasoning_summary": "AI analysis disabled by configuration",
                "limitations": ["AI globally disabled"],
                "provider_attempts": 0,
                "attempt_log": [],
                "authoritative": False,
                "timestamp": time.time()
            }

        # Run gatekeeper
        gatekeeper = self._get_gatekeeper()
        gatekeeper_result = gatekeeper.evaluate(
            evidence_data,
            initial_prediction=initial_prediction,
            initial_confidence=initial_confidence
        )

        if not gatekeeper_result["ai_required"]:
            return {
                "status": "NOT_RUN",
                "ai_required": False,
                "ai_called": False,
                "provider": None,
                "model": None,
                "gatekeeper": gatekeeper_result,
                "assessment": None,
                "confidence": 0.0,
                "supporting_evidence": [],
                "contradictory_evidence": [],
                "observations": [],
                "reasoning_summary": gatekeeper_result["reason"],
                "limitations": [],
                "provider_attempts": 0,
                "attempt_log": [],
                "authoritative": False,
                "timestamp": time.time()
            }

        # AI is recommended — prepare evidence payload
        from User.services.nikhil.evidence_normalizer import EvidenceNormalizer

        initial_ml = {
            "class": initial_prediction or "Unknown",
            "confidence": initial_confidence or 0.0
        }

        # Normalize evidence for AI input
        normalized = {}
        for key in ["webpage", "network", "visual", "threat_intelligence", "prompt_injection"]:
            raw = evidence_data.get(key, {})
            normalized[key] = EvidenceNormalizer.normalize(key, raw)

        ai_payload = EvidenceNormalizer.build_ai_input(initial_ml, normalized)

        # Call provider manager with failover
        provider_manager = self._get_provider_manager()
        manager_result = provider_manager.analyze_with_failover(ai_payload)

        # Build final AI result
        result = {
            "status": manager_result["status"],
            "ai_required": True,
            "ai_called": manager_result["ai_called"],
            "provider": manager_result.get("provider"),
            "model": manager_result.get("model"),
            "gatekeeper": gatekeeper_result,
            "provider_attempts": manager_result.get("provider_attempts", 0),
            "attempt_log": manager_result.get("attempt_log", []),
            "failover_reason": manager_result.get("failover_reason"),
            "total_latency_ms": manager_result.get("total_latency_ms", 0),
            "authoritative": False,  # AI is NEVER the final authority
            "timestamp": time.time()
        }

        # Extract AI assessment if successful
        ai_result = manager_result.get("result")
        if ai_result and manager_result["status"] == "SUCCESS":
            result.update({
                "assessment": ai_result.get("assessment"),
                "confidence": ai_result.get("confidence", 0.0),
                "supporting_evidence": ai_result.get("supporting_evidence", []),
                "contradictory_evidence": ai_result.get("contradictory_evidence", []),
                "observations": ai_result.get("observations", []),
                "reasoning_summary": ai_result.get("reasoning_summary", ""),
                "limitations": ai_result.get("limitations", []),
            })
        else:
            fail_reason = manager_result.get("failover_reason") or "Deterministic evidence insufficient; AI provider unavailable"
            result.update({
                "assessment": None,
                "confidence": 0.0,
                "supporting_evidence": [],
                "contradictory_evidence": [],
                "observations": [],
                "failover_reason": fail_reason,
                "reasoning_summary": fail_reason,
                "limitations": ["AI analysis unavailable — continuing with deterministic evidence"],
            })

        return result
