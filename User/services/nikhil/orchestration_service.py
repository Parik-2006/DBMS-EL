import time
from User.services.nikhil.webpage_analyzer import WebpageAnalyzer
from User.services.nikhil.network_analyzer import NetworkAnalyzer
from User.services.nikhil.ai_analyzer import AIAnalyzer
from User.services.nikhil.additional_evidence import AdditionalEvidenceCollector
from User.services.nikhil.mongodb_repository import MongoDBRepository

class FallbackOrchestrator:
    """Service to orchestrate deep analysis modules"""
    
    def __init__(self):
        self.webpage_analyzer = WebpageAnalyzer()
        self.network_analyzer = NetworkAnalyzer()
        self.ai_analyzer = AIAnalyzer()
        self.additional_collector = AdditionalEvidenceCollector()
        self.mongo_repo = MongoDBRepository()

    def perform_deep_analysis(self, scan_id, url):
        """
        Orchestrate modules and store evidence
        
        Returns:
            dict: Structured analysis result
        """
        start_time = time.time()
        
        # 1. Collect Evidence
        webpage_evidence = self.webpage_analyzer.analyze_webpage(url)
        network_evidence = self.network_analyzer.analyze_network(url)
        ai_evidence = self.ai_analyzer.analyze_with_ai({"webpage": webpage_evidence, "network": network_evidence})
        additional_evidence = self.additional_collector.collect_additional_evidence(url)
        
        evidence_data = {
            "scan_id": scan_id,
            "url": url,
            "analysis_status": "COMPLETED",
            "webpage": webpage_evidence,
            "network": network_evidence,
            "ai_analysis": ai_evidence,
            "additional_evidence": additional_evidence,
            "timestamps": {
                "started_at": start_time,
                "completed_at": time.time()
            }
        }
        
        # 2. Store Evidence
        mongo_doc_id = self.mongo_repo.store_evidence(evidence_data)
        
        # 3. Finalize result (to be implemented)
        return evidence_data, mongo_doc_id
