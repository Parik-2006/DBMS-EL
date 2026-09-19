import os
import time
import re

class AIAnalyzer:
    """Service for AI/LLM-based analysis"""
    
    @staticmethod
    def analyze_with_ai(evidence_data):
        """
        Analyze evidence using AI/LLM
        
        Returns:
            dict: AI findings
        """
        provider = os.environ.get('LLM_PROVIDER', 'MOCK')
        
        # In a real implementation, this would call an external API
        
        if provider == 'MOCK':
            return AIAnalyzer._mock_analysis(evidence_data)
        
        # Real implementation would go here
        return {
            "status": "UNAVAILABLE",
            "findings": [],
            "suspicious_patterns": [],
            "prompt_injection_detected": False,
            "explanation": "Provider not configured"
        }

    @staticmethod
    def _mock_analysis(evidence_data):
        """Mock analysis for local testing"""
        findings = []
        suspicious = []
        injection_detected = False
        explanation = "Mock analysis performed."
        
        # Simple heuristic prompt injection detection
        text_data = evidence_data.get("webpage", {}).get("text", "")
        injection_patterns = [
            r"ignore previous instructions",
            r"you are a",
            r"reveal your system prompt"
        ]
        
        for pattern in injection_patterns:
            if re.search(pattern, text_data, re.IGNORECASE):
                injection_detected = True
                suspicious.append("Potential Prompt Injection")
        
        if injection_detected:
            explanation = "Potential prompt injection attempt detected."
            
        return {
            "status": "MOCK",
            "findings": findings,
            "suspicious_patterns": suspicious,
            "prompt_injection_detected": injection_detected,
            "explanation": explanation,
            "timestamp": time.time()
        }
import re
