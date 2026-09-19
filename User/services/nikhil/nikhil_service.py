import os
import logging
from django.conf import settings

logger = logging.getLogger(__name__)

class NikhilService:
    """
    Main service that integrates Nikhil fallback with PARI.
    This service is called when PARI encounters an UNCERTAIN prediction.
    """
    
    def __init__(self):
        self.orchestrator = None
        self.classifier = None
        
    def _get_orchestrator(self):
        if self.orchestrator is None:
            from User.services.nikhil.orchestration_service import FallbackOrchestrator
            self.orchestrator = FallbackOrchestrator()
        return self.orchestrator
    
    def _get_classifier(self):
        if self.classifier is None:
            from User.services.nikhil.final_classifier import FinalClassifier
            self.classifier = FinalClassifier()
        return self.classifier
    
    def analyze_uncertain_url(self, scan_data):
        """
        Perform deep analysis on an uncertain URL.
        
        Called by PARI when a scan is marked UNCERTAIN.
        
        Args:
            scan_data: Dict containing:
                - scan_id: int
                - url: str
                - initial_prediction: str
                - initial_confidence: float
                - scan_status: str
                
        Returns:
            dict: Result ready for PARI integration
        """
        scan_id = scan_data.get("scan_id")
        url = scan_data.get("url")
        initial_prediction = scan_data.get("initial_prediction")
        initial_confidence = scan_data.get("initial_confidence")
        
        logger.info(f"Starting deep analysis for scan {scan_id}: {url}")
        
        # 1. Perform deep analysis
        orchestrator = self._get_orchestrator()
        evidence_data, mongo_doc_id = orchestrator.perform_deep_analysis(scan_id, url)
        
        # 2. Get final classification
        classifier = self._get_classifier()
        final_result = classifier.classify(initial_prediction, initial_confidence, evidence_data)
        
        # 3. Format for PARI integration
        result = {
            "scan_id": scan_id,
            "analysis_status": "COMPLETED",
            "final_classification": final_result["final_classification"],
            "risk_level": final_result["risk_level"],
            "risk_score": final_result["risk_score"],
            "evidence_summary": final_result["evidence_summary"],
            "threat_indicators": final_result.get("threat_indicators", []),
            "mongo_document_reference": mongo_doc_id,
            "original_prediction": initial_prediction,
            "original_confidence": initial_confidence
        }
        
        logger.info(f"Deep analysis complete for scan {scan_id}: {result['final_classification']}")
        
        return result