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
        
        # 1. Orchestrate multi-module evidence collection (incl. AI gatekeeper + providers)
        orchestrator = self._get_orchestrator()
        evidence_data, mongo_doc_id = orchestrator.perform_deep_analysis(
            scan_id, url,
            initial_prediction=initial_prediction,
            initial_confidence=initial_confidence
        )
        
        # 2. Perform multi-family evidence corroboration & rule-based classification
        classifier = self._get_classifier()
        final_result = classifier.classify(initial_prediction, initial_confidence, evidence_data)
        
        # 3. Update MongoDB case record with final corroboration and classification
        try:
            evidence_data["corroboration"] = final_result.get("corroboration", {})
            evidence_data["final_analysis"] = {
                "classification": final_result["final_classification"],
                "risk_level": final_result["risk_level"],
                "risk_score": final_result["risk_score"],
                "evidence_summary": final_result.get("evidence_summary", ""),
                "limitations": []
            }
            mongo_repo = self._get_mongo_repo()
            mongo_repo.store_evidence(evidence_data)
        except Exception as e:
            logger.warning(f"Failed to update MongoDB with final classification: {e}")

        # 4. Extract module statuses for UI display
        ai_data = evidence_data.get("ai_analysis", {})
        ai_status = ai_data.get("status", "NOT_RUN")
        
        module_statuses = {
            "webpage": evidence_data.get("webpage", {}).get("status", "UNKNOWN"),
            "network": evidence_data.get("network", {}).get("status", "UNKNOWN"),
            "visual": evidence_data.get("visual", {}).get("status", "UNAVAILABLE"),
            "threat_intelligence": evidence_data.get("threat_intelligence", {}).get("status", "UNAVAILABLE"),
            "prompt_injection": "DETECTED" if evidence_data.get("prompt_injection", {}).get("prompt_injection_detected") else "NOT_DETECTED",
            "ai": ai_status
        }

        # 5. Build AI display info
        ai_display = {
            "status": ai_status,
            "provider": ai_data.get("provider"),
            "model": ai_data.get("model"),
            "assessment": ai_data.get("assessment"),
            "ai_required": ai_data.get("ai_required", False),
            "ai_called": ai_data.get("ai_called", False),
            "provider_attempts": ai_data.get("provider_attempts", 0),
            "gatekeeper_reason": ai_data.get("gatekeeper", {}).get("reason", ""),
            "failover_reason": ai_data.get("failover_reason"),
            "reasoning_summary": ai_data.get("reasoning_summary", ""),
        }

        # 5b. Build Threat Intel display info
        ti_data = evidence_data.get("threat_intelligence", {})
        ti_summary = ti_data.get("summary", {})
        ti_sources = ti_data.get("sources", {})
        threat_intel_display = {
            "status": ti_data.get("status", "UNAVAILABLE"),
            "ui_summary": ti_summary.get("threat_intel_ui_summary", "Local SQL correlation active"),
            "positive_hits": ti_summary.get("positive_hits", 0),
            "sources_available": ti_summary.get("sources_available", 0),
            "threatfox": ti_sources.get("threatfox", {}).get("status", "NOT_RUN"),
            "threatfox_hits": ti_sources.get("threatfox", {}).get("hits", 0),
            "urlhaus": ti_sources.get("urlhaus", {}).get("status", "NOT_RUN"),
            "urlhaus_hits": ti_sources.get("urlhaus", {}).get("hits", 0),
            "abuseipdb": ti_sources.get("abuseipdb", {}).get("status", "NOT_RUN"),
            "abuseipdb_score": ti_sources.get("abuseipdb", {}).get("abuse_confidence_score", 0),
            "local_sql_scans": ti_sources.get("local_sql", {}).get("previous_scans_count", 0),
            "local_sql_malicious": ti_sources.get("local_sql", {}).get("known_malicious_in_domain", 0),
            "trusted_domain": ti_sources.get("trusted_domain", {}).get("category") if ti_sources.get("trusted_domain", {}).get("is_known") else "Not Listed",
        }

        # 6. Assemble PARI contract payload
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
            "module_statuses": module_statuses,
            "ai_display": ai_display,
            "threat_intel_display": threat_intel_display,
        }
        
        logger.info(f"Fallback complete for Scan {scan_id}: Final {result['final_classification']} (Risk: {result['risk_level']})")
        return result