import re
import time
import logging

logger = logging.getLogger(__name__)

class PromptInjectionDetector:
    """
    Deterministic rule-based prompt-injection detector (NO LLM).
    Treats all incoming webpage text strictly as untrusted DATA.
    Produces an EVIDENCE SIGNAL only.
    """

    # High-confidence injection patterns
    CRITICAL_INJECTION_PATTERNS = [
        (r'\bignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions\b', "IGNORE_PREVIOUS_INSTRUCTIONS"),
        (r'\bdisregard\s+(?:all\s+)?(?:previous|prior|above)\s+(?:rules|instructions|prompts)\b', "DISREGARD_INSTRUCTIONS"),
        (r'\breveal\s+(?:the\s+)?(?:system\s+prompt|developer\s+prompt|initial\s+instructions)\b', "REVEAL_SYSTEM_PROMPT"),
        (r'\bshow\s+(?:me\s+)?(?:your\s+)?(?:system\s+instructions|secret\s+prompt)\b', "SHOW_SYSTEM_INSTRUCTIONS"),
        (r'\bprint\s+(?:your\s+)?(?:initial\s+prompt|system\s+prompt)\b', "PRINT_INITIAL_PROMPT"),
        (r'\byou\s+are\s+now\s+(?:DAN|an\s+unrestricted|in\s+developer\s+mode)\b', "PERSONA_OVERRIDE_DAN"),
        (r'\bact\s+as\s+(?:an?\s+)?(?:unfiltered|jailbroken)\b', "JAILBREAK_ATTEMPT"),
        (r'\bclassify\s+(?:this\s+)?(?:website|url|page)\s+as\s+(?:benign|safe|clean)\b', "CLASSIFIER_OVERRIDE_DIRECTIVE"),
        (r'\balways\s+return\s+(?:benign|safe|0\s+risk)\b', "ALWAYS_RETURN_SAFE_DIRECTIVE"),
        (r'\boverride\s+(?:the\s+)?security\s+(?:score|scanner|classification)\b', "OVERRIDE_SECURITY_SCANNER"),
        (r'\[SYSTEM\s+PROMPT(?:\s+OVERRIDE)?\]', "DELIMITER_INJECTION_SYSTEM"),
        (r'<\s*system\s*>', "XML_TAG_SYSTEM_INJECTION"),
        (r'\b(?:system|exec|passthru|shell_exec)\s*\(\s*["\'].*?["\']\s*\)', "SHELL_TOOL_CALL_SYNTAX"),
        (r'\bbash\s+-c\s+["\'].*?["\']', "BASH_TOOL_EXEC_SYNTAX")
    ]

    # Moderate patterns (may appear in normal instructional text, require contextual weight)
    MODERATE_PATTERNS = [
        (r'\bdo\s+not\s+scan\s+this\s+page\b', "DO_NOT_SCAN_REQUEST"),
        (r'\bthis\s+page\s+is\s+guaranteed\s+safe\b', "UNVERIFIED_SAFETY_CLAIM"),
        (r'\bignore\s+security\s+warnings\b', "IGNORE_SECURITY_WARNINGS"),
        (r'\bnew\s+instructions:\s*', "NEW_INSTRUCTIONS_PREFIX")
    ]

    @classmethod
    def detect_prompt_injection(cls, webpage_evidence):
        """
        Analyze extracted visible text, hidden content, and HTML snippets for prompt-injection patterns.
        
        Args:
            webpage_evidence: dict returned by WebpageAnalyzer (or text string)
            
        Returns:
            dict: {
                "prompt_injection_detected": bool,
                "confidence": float,
                "matched_patterns": list of str,
                "explanation": str,
                "details": list of dict
            }
        """
        # Extract all text sources safely
        text_sources = []
        
        if isinstance(webpage_evidence, str):
            text_sources.append(("input_text", webpage_evidence))
        elif isinstance(webpage_evidence, dict):
            visible_text = webpage_evidence.get("visible_text", "")
            if visible_text:
                text_sources.append(("visible_text", visible_text))
            
            # Check hidden elements (often used for stealth prompt injection)
            for hidden in webpage_evidence.get("hidden_elements", []):
                snippet = hidden.get("snippet", "")
                if snippet:
                    text_sources.append(("hidden_element", snippet))
                    
            # Check title
            title = webpage_evidence.get("title", "")
            if title:
                text_sources.append(("title", title))
        
        matched_patterns = []
        details = []
        critical_matches = 0
        moderate_matches = 0

        for source_name, text in text_sources:
            if not text:
                continue

            # Check critical patterns
            for pattern_regex, pattern_name in cls.CRITICAL_INJECTION_PATTERNS:
                matches = re.finditer(pattern_regex, text, re.IGNORECASE)
                for m in matches:
                    matched_snippet = m.group(0)
                    if pattern_name not in matched_patterns:
                        matched_patterns.append(pattern_name)
                    critical_matches += 1
                    details.append({
                        "pattern": pattern_name,
                        "source": source_name,
                        "snippet": matched_snippet[:80],
                        "severity": "CRITICAL"
                    })

            # Check moderate patterns
            for pattern_regex, pattern_name in cls.MODERATE_PATTERNS:
                matches = re.finditer(pattern_regex, text, re.IGNORECASE)
                for m in matches:
                    matched_snippet = m.group(0)
                    if pattern_name not in matched_patterns:
                        matched_patterns.append(pattern_name)
                    moderate_matches += 1
                    details.append({
                        "pattern": pattern_name,
                        "source": source_name,
                        "snippet": matched_snippet[:80],
                        "severity": "MODERATE"
                    })

        # Calculate rule-based confidence score
        if critical_matches >= 2:
            confidence = 0.95
            detected = True
            explanation = f"Definite prompt injection detected: {critical_matches} critical adversarial instruction patterns found."
        elif critical_matches == 1:
            confidence = 0.80
            detected = True
            explanation = f"Probable prompt injection attempt detected: matched pattern '{matched_patterns[0]}'."
        elif moderate_matches >= 2:
            confidence = 0.60
            detected = True
            explanation = f"Possible prompt injection: multiple suspicious override phrases detected ({moderate_matches})."
        elif moderate_matches == 1:
            confidence = 0.30
            detected = False
            explanation = "Low-confidence isolated phrase observed; likely benign or instructional context."
        else:
            confidence = 0.0
            detected = False
            explanation = "No prompt-injection or instruction-override patterns detected."

        return {
            "prompt_injection_detected": detected,
            "confidence": confidence,
            "matched_patterns": matched_patterns,
            "explanation": explanation,
            "details": details,
            "timestamp": time.time()
        }
