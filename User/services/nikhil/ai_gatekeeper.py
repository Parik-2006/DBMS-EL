"""
AI Gatekeeper — Deterministic Decision Module
Decides whether AI analysis is warranted based on collected evidence.
Does NOT use any LLM. Pure rule-based logic.
"""
import logging

logger = logging.getLogger(__name__)


class AIGatekeeper:
    """
    Deterministic gatekeeper that evaluates whether AI analysis would
    meaningfully improve the investigation outcome.

    AI SHOULD NOT be called when:
    - Deterministic evidence is already strongly corroborated
    - No meaningful contradiction exists
    - Final classifier has enough evidence

    AI SHOULD be considered when:
    - Evidence families conflict
    - Webpage meaning is ambiguous
    - Visual/text evidence disagree
    - Threat intelligence conflicts with observed behavior
    - Prompt injection context is ambiguous
    - Final result would otherwise remain Unknown and meaningful evidence exists
    """

    @classmethod
    def evaluate(cls, evidence_data, initial_prediction=None, initial_confidence=None):
        """
        Evaluate whether AI analysis is necessary.

        Args:
            evidence_data: dict with collector results
            initial_prediction: str initial ML class
            initial_confidence: float initial ML confidence

        Returns:
            dict: {
                "ai_required": bool,
                "reason": str,
                "priority": "LOW"|"MEDIUM"|"HIGH",
                "triggers": list[str]
            }
        """
        triggers = []
        priority = "LOW"

        webpage = evidence_data.get("webpage", {})
        network = evidence_data.get("network", {})
        visual = evidence_data.get("visual", {})
        threat_intel = evidence_data.get("threat_intelligence", {})
        prompt_inj = evidence_data.get("prompt_injection", {})

        wp_status = webpage.get("status", "NOT_RUN")
        net_status = network.get("status", "NOT_RUN")
        wp_indicators = webpage.get("indicators", [])

        # ---- Check for strong deterministic evidence ----

        # Count available evidence families
        available_families = 0
        if wp_status == "SUCCESS":
            available_families += 1
        if net_status == "SUCCESS":
            available_families += 1
        if visual.get("status") == "SUCCESS":
            available_families += 1
        if threat_intel.get("status") not in (None, "NOT_RUN"):
            available_families += 1

        # Strong malicious signals — no AI needed
        strong_malicious_indicators = [
            "PASSWORD_FORM", "CROSS_DOMAIN_FORM", "CREDENTIAL_HARVESTING_TEXT",
            "DEFACEMENT_TEXT", "SUSPICIOUS_DOWNLOAD"
        ]
        strong_count = sum(1 for ind in wp_indicators if ind in strong_malicious_indicators)

        if strong_count >= 2:
            return {
                "ai_required": False,
                "reason": f"Strong deterministic malicious evidence ({strong_count} indicators) — AI not needed",
                "priority": "LOW",
                "triggers": []
            }

        # Strong benign signals — clean page, valid SSL, no indicators
        ssl_info = network.get("ssl", {})
        is_clean_webpage = wp_status == "SUCCESS" and len(wp_indicators) == 0
        has_valid_ssl = ssl_info.get("verified") is True
        no_prompt_injection = not prompt_inj.get("prompt_injection_detected", False)
        ml_is_malicious = initial_prediction in ("Phishing", "Malware", "Defacement")

        if is_clean_webpage and has_valid_ssl and no_prompt_injection and available_families >= 2 and not ml_is_malicious:
            return {
                "ai_required": False,
                "reason": "Clean webpage + valid SSL + no injection — deterministic evidence sufficient",
                "priority": "LOW",
                "triggers": []
            }

        # ---- Check for conditions where AI would help ----

        # Conflict: clean webpage but suspicious network
        if is_clean_webpage and not has_valid_ssl and net_status == "SUCCESS":
            triggers.append("WEBPAGE_NETWORK_CONFLICT")
            priority = "MEDIUM"

        # Conflict: initial ML says malicious but webpage looks clean
        if initial_prediction in ("Phishing", "Malware", "Defacement") and is_clean_webpage:
            triggers.append("ML_WEBPAGE_CONFLICT")
            priority = "MEDIUM"

        # Prompt injection detected — ambiguous context
        if prompt_inj.get("prompt_injection_detected"):
            pi_confidence = prompt_inj.get("confidence", 0)
            if 0.5 <= pi_confidence <= 0.85:
                triggers.append("AMBIGUOUS_PROMPT_INJECTION")
                priority = "HIGH"

        # Insufficient evidence — would result in Unknown
        if available_families < 2 and wp_status == "SUCCESS" and len(wp_indicators) > 0:
            triggers.append("INSUFFICIENT_CORROBORATION")
            priority = "MEDIUM"

        # Single weak indicator — AI interpretation could help
        if strong_count == 1 and available_families < 3:
            triggers.append("SINGLE_WEAK_INDICATOR")
            priority = "MEDIUM"

        # Threat intel conflict
        local_correl = threat_intel.get("local_correlation", {})
        known_malicious = local_correl.get("known_malicious_in_domain", 0)
        if known_malicious > 0 and is_clean_webpage:
            triggers.append("THREAT_INTEL_WEBPAGE_CONFLICT")
            priority = "HIGH"

        ai_required = len(triggers) > 0

        if ai_required:
            reason = f"AI recommended: {', '.join(triggers)}"
        else:
            reason = "Deterministic evidence sufficient — AI not required"

        logger.info(f"AIGatekeeper decision: ai_required={ai_required}, priority={priority}, triggers={triggers}")

        return {
            "ai_required": ai_required,
            "reason": reason,
            "priority": priority,
            "triggers": triggers
        }
