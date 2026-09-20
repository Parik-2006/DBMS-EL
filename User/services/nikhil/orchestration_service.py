import time
import logging
from User.services.nikhil.webpage_analyzer import WebpageAnalyzer
from User.services.nikhil.network_analyzer import NetworkAnalyzer
from User.services.nikhil.visual_analyzer import VisualAnalyzer
from User.services.nikhil.threat_intel import ThreatIntelService
from User.services.nikhil.prompt_injection import PromptInjectionDetector
from User.services.nikhil.ai_analyzer import AIAnalyzer
from User.services.nikhil.mongodb_repository import MongoDBRepository

logger = logging.getLogger(__name__)

class FallbackOrchestrator:
    """
    Orchestrates all deep analysis evidence-gathering modules.
    Fault-tolerant: Failure of any single module does NOT crash the scan pipeline.
    """
    
    def __init__(self):
        self.webpage_analyzer = WebpageAnalyzer()
        self.network_analyzer = NetworkAnalyzer()
        self.visual_analyzer = VisualAnalyzer()
        self.threat_intel_service = ThreatIntelService()
        self.prompt_injection_detector = PromptInjectionDetector()
        self.ai_analyzer = AIAnalyzer()
        self.mongo_repo = MongoDBRepository()

    def perform_deep_analysis(self, scan_id, url):
        """
        Execute deep analysis modules safely and assemble structured evidence.
        
        Args:
            scan_id: int unique scan identifier
            url: str target URL
            
        Returns:
            tuple: (dict evidence_data, str mongo_doc_id)
        """
        start_time = time.time()
        logger.info(f"Orchestrating fallback deep analysis for Scan {scan_id}: {url}")

        # 1. Webpage / DOM Analysis
        try:
            webpage_evidence = self.webpage_analyzer.analyze_webpage(url)
        except Exception as e:
            logger.error(f"Webpage analysis exception for Scan {scan_id}: {e}")
            webpage_evidence = {"status": "ERROR", "error": str(e), "indicators": []}

        # 2. Network / DNS / SSL Analysis
        try:
            network_evidence = self.network_analyzer.analyze_network(url)
        except Exception as e:
            logger.error(f"Network analysis exception for Scan {scan_id}: {e}")
            network_evidence = {"status": "ERROR", "error": str(e), "network_findings": []}

        # 3. Visual / Screenshot Analysis (isolated browser or UNAVAILABLE)
        try:
            visual_evidence = self.visual_analyzer.analyze_visual(url, scan_id=scan_id)
        except Exception as e:
            logger.error(f"Visual analysis exception for Scan {scan_id}: {e}")
            visual_evidence = {"status": "UNAVAILABLE", "error": str(e), "visual_findings": []}

        # 4. Threat Intelligence & Local SQL Correlation
        try:
            resolved_ip = network_evidence.get("ip_resolution", {}).get("primary_ip")
            domain_name = network_evidence.get("domain")
            threat_intel_evidence = self.threat_intel_service.analyze_threat_intel(
                url, domain=domain_name, ip=resolved_ip
            )
        except Exception as e:
            logger.error(f"Threat intelligence exception for Scan {scan_id}: {e}")
            threat_intel_evidence = {"status": "ERROR", "error": str(e), "external_indicators": []}

        # 5. Rule-Based Prompt-Injection Detection (No LLM)
        try:
            prompt_injection_evidence = self.prompt_injection_detector.detect_prompt_injection(webpage_evidence)
        except Exception as e:
            logger.error(f"Prompt injection detection exception for Scan {scan_id}: {e}")
            prompt_injection_evidence = {"prompt_injection_detected": False, "error": str(e), "matched_patterns": []}

        # 6. AI Analysis Module (Explicitly MOCK / UNAVAILABLE)
        try:
            ai_evidence = self.ai_analyzer.analyze_with_ai({
                "webpage": webpage_evidence,
                "network": network_evidence
            })
        except Exception as e:
            ai_evidence = {"status": "UNAVAILABLE", "error": str(e)}

        # Complete evidence bundle
        evidence_data = {
            "scan_id": scan_id,
            "url": url,
            "analysis_status": "COMPLETED",
            "webpage": webpage_evidence,
            "network": network_evidence,
            "visual": visual_evidence,
            "threat_intelligence": threat_intel_evidence,
            "prompt_injection": prompt_injection_evidence,
            "ai_analysis": ai_evidence,
            "timestamps": {
                "started_at": start_time,
                "completed_at": time.time(),
                "duration_seconds": round(time.time() - start_time, 2)
            }
        }

        # Store in MongoDB deep_analysis_cases (resilient with fallback cache)
        mongo_doc_id = self.mongo_repo.store_evidence(evidence_data)

        return evidence_data, mongo_doc_id
