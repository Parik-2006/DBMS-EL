import os
import time

class AIAnalyzer:
    """
    AI / LLM Analysis Interface.
    
    IMPORTANT ARCHITECTURAL NOTICE:
    ==============================
    REAL LLM / GEMINI IS EXCLUDED FROM THIS PHASE.
    REAL LLM: NOT IMPLEMENTED — FUTURE PHASE.
    
    This module remains explicitly locked as MOCK / UNAVAILABLE.
    Mock AI evidence MUST NOT be treated as real AI evidence,
    and CANNOT independently create an authoritative final classification.
    """
    
    @staticmethod
    def analyze_with_ai(evidence_data):
        """
        AI analyzer interface stub for future multimodal LLM integration.
        Currently returns MOCK / UNAVAILABLE status.
        
        Args:
            evidence_data: dict containing gathered evidence
            
        Returns:
            dict: Structured AI analysis status (MOCK/UNAVAILABLE)
        """
        # Strictly MOCK/UNAVAILABLE - Real LLM integration is deferred to future phase
        return {
            "status": "MOCK",
            "model": "MOCK_AI_STUB",
            "note": "REAL LLM NOT IMPLEMENTED IN THIS PHASE — FUTURE PHASE",
            "findings": [],
            "suspicious_patterns": [],
            "prompt_injection_assessment": {
                "status": "DEFERRED_TO_RULE_BASED_DETECTOR"
            },
            "authoritative": False,
            "timestamp": time.time()
        }
