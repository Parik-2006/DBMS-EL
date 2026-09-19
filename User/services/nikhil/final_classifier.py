class FinalClassifier:
    """Service to determine final classification based on gathered evidence"""
    
    @staticmethod
    def classify(initial_prediction, initial_confidence, evidence):
        """
        Determine final classification
        
        Returns:
            dict: Final classification result
        """
        # Logic to combine evidence
        
        # Example rule: if AI says Phishing and Webpage says Suspicious form -> Phishing
        
        final_class = "Unknown"
        risk_score = 0.5
        risk_level = "MEDIUM"
        
        # Simple placeholder logic for now
        if evidence["ai_analysis"].get("prompt_injection_detected", False):
            final_class = "Phishing"
            risk_level = "HIGH"
            risk_score = 0.9
        elif "PASSWORD_FORM" in evidence["webpage"].get("suspicious_elements", []):
            final_class = "Phishing"
            risk_level = "HIGH"
            risk_score = 0.8
        else:
            final_class = initial_prediction if initial_prediction else "Unknown"
            risk_score = 0.5
        
        threat_indicators = []
        for element in evidence["webpage"].get("suspicious_elements", []):
            threat_indicators.append(f"WEBPAGE:{element}")
            
        return {
            "final_classification": final_class,
            "risk_level": risk_level,
            "risk_score": risk_score,
            "evidence_summary": evidence["ai_analysis"].get("explanation", "Analysis completed."),
            "threat_indicators": threat_indicators
        }
