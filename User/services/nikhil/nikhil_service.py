import logging
from django.conf import settings

logger = logging.getLogger(__name__)

class NikhilService:
    """
    Main service that coordinates the Nikhil fallback pipeline with PARI.
    Called when PARI encounters an UNCERTAIN prediction (confidence < 0.75).
    """
    
    def __init__(self):
        self.orchestrator = None
        self.classifier = None
        self.mongo_repo = None
        
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

    def _get_mongo_repo(self):
        if self.mongo_repo is None:
            from User.services.nikhil.mongodb_repository import MongoDBRepository
            self.mongo_repo = MongoDBRepository()
        return self.mongo_repo
    
    def analyze_uncertain_url(self, scan_data):
        """
        Perform deep evidence analysis and multi-family corroboration on an uncertain URL.
        
        Args:
            scan_data: Dict containing:
                - scan_id: int
                - url: str
                - initial_prediction: str
                - initial_confidence: float
                - scan_status: str
                
        Returns:
            dict: Comprehensive result adhering to the PARI fallback return contract
        """
        scan_id = scan_data.get("scan_id")
        url = scan_data.get("url")
        initial_prediction = scan_data.get("initial_prediction")
        initial_confidence = scan_data.get("initial_confidence")
        
        logger.info(f"Initiating evidence-driven fallback for Scan {scan_id}: {url}")
        
        # 1. Orchestrate multi-module evidence collection
        orchestrator = self._get_orchestrator()
        evidence_data, mongo_doc_id = orchestrator.perform_deep_analysis(scan_id, url)
        
        # 2. Perform multi-family evidence corroboration & rule-based classification
        classifier = self._get_classifier()
        final_result = classifier.classify(initial_prediction, initial_confidence, evidence_data)
        
        # 3. Update MongoDB case record with final corroboration and classification
        try:
            evidence_data["corroboration"] = final_result.get("corroboration", {})
            evidence_data["final_analysis"] = {
                "classification": final_result["final_classification"],
                "risk_level": final_result["risk_level"],
                "risk_score": final_result["risk_score"]
            }
            mongo_repo = self._get_mongo_repo()
            mongo_repo.store_evidence(evidence_data)
        except Exception as e:
            logger.warning(f"Failed to update MongoDB with final classification: {e}")

        # 4. Extract module statuses for UI display
        module_statuses = {
            "webpage": evidence_data.get("webpage", {}).get("status", "UNKNOWN"),
            "network": evidence_data.get("network", {}).get("status", "UNKNOWN"),
            "visual": evidence_data.get("visual", {}).get("status", "UNAVAILABLE"),
            "threat_intelligence": evidence_data.get("threat_intelligence", {}).get("status", "UNAVAILABLE"),
            "prompt_injection": "DETECTED" if evidence_data.get("prompt_injection", {}).get("prompt_injection_detected") else "NOT_DETECTED",
            "ai": evidence_data.get("ai_analysis", {}).get("status", "MOCK")
        }

        # 5. Assemble PARI contract payload
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
            "original_confidence": initial_confidence,
            "evidence_breakdown": final_result.get("evidence_breakdown", {}),
            "corroboration": final_result.get("corroboration", {}),
            "module_statuses": module_statuses
        }
        
        logger.info(f"Fallback complete for Scan {scan_id}: Final {result['final_classification']} (Risk: {result['risk_level']})")
        return result