"""
Nikhil Fallback Orchestrator — Deterministic Evidence Collection Pipeline.
Orchestrates all six collectors, AI gatekeeper, and AI provider chain.
The orchestrator is NORMAL DETERMINISTIC CODE — no LLM decides the workflow.
"""
import time
import logging
from User.services.nikhil.webpage_analyzer import WebpageAnalyzer
from User.services.nikhil.network_analyzer import NetworkAnalyzer
from User.services.nikhil.visual_analyzer import VisualAnalyzer
from User.services.nikhil.threat_intel import ThreatIntelService
from User.services.nikhil.prompt_injection import PromptInjectionDetector
from User.services.nikhil.ai_analyzer import AIAnalyzer
from User.services.nikhil.trusted_domains import TrustedDomainService
from User.services.nikhil.mongodb_repository import MongoDBRepository

logger = logging.getLogger(__name__)


class FallbackOrchestrator:
    """
    Orchestrates all deep analysis evidence-gathering modules.
    Fault-tolerant: Failure of any single module does NOT crash the scan pipeline.

    Required order:
    1. Webpage evidence
    2. Network evidence
    3. Visual evidence
    4. Threat intelligence (incl. trusted domain)
    5. Prompt-injection detection
    6. AI analysis (gatekeeper + provider manager)

    Bounded total runtime.
    """

    MAX_TOTAL_SECONDS = 60  # Overall fallback timeout

    def __init__(self):
        self.webpage_analyzer = WebpageAnalyzer()
        self.network_analyzer = NetworkAnalyzer()
        self.visual_analyzer = VisualAnalyzer()
        self.threat_intel_service = ThreatIntelService()
        self.prompt_injection_detector = PromptInjectionDetector()
        self.ai_analyzer = AIAnalyzer()
        self.trusted_domain_service = TrustedDomainService()
        self.mongo_repo = MongoDBRepository()

    def perform_deep_analysis(self, scan_id, url, initial_prediction=None, initial_confidence=None):
        """
        Execute deep analysis modules safely and assemble structured evidence.

        Args:
            scan_id: int unique scan identifier
            url: str target URL
            initial_prediction: str initial ML class (optional)
            initial_confidence: float initial ML confidence (optional)

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
            webpage_evidence = {"status": "ERROR", "error": str(e), "indicators": [], "findings": []}

        # 2. Network / DNS / SSL Analysis
        try:
            network_evidence = self.network_analyzer.analyze_network(url)
        except Exception as e:
            logger.error(f"Network analysis exception for Scan {scan_id}: {e}")
            network_evidence = {"status": "ERROR", "error": str(e), "network_findings": []}

        # 3. Visual / Screenshot Analysis
        try:
            visual_evidence = self.visual_analyzer.analyze_visual(url, scan_id=scan_id)
        except Exception as e:
            logger.error(f"Visual analysis exception for Scan {scan_id}: {e}")
            visual_evidence = {"status": "UNAVAILABLE", "error": str(e), "visual_findings": []}

        # 4. Threat Intelligence & Trusted Domain Intelligence
        try:
            resolved_ip = network_evidence.get("ip_resolution", {}).get("primary_ip")
            domain_name = network_evidence.get("domain")
            threat_intel_evidence = self.threat_intel_service.analyze_threat_intel(
                url, domain=domain_name, ip=resolved_ip
            )
        except Exception as e:
            logger.error(f"Threat intelligence exception for Scan {scan_id}: {e}")
            threat_intel_evidence = {"status": "ERROR", "error": str(e), "external_indicators": []}

        # 4b. Trusted domain lookup (merged into threat intel)
        try:
            domain_lookup = self.trusted_domain_service.lookup_domain(url)
            url_features = self.trusted_domain_service.extract_url_features(url)
            threat_intel_evidence["trusted_domain"] = domain_lookup
            threat_intel_evidence["url_features"] = url_features
        except Exception as e:
            logger.warning(f"Trusted domain service error for Scan {scan_id}: {e}")
            threat_intel_evidence["trusted_domain"] = {"is_known": False, "evidence_type": "ERROR"}
            threat_intel_evidence["url_features"] = {"error": str(e)}

        # 5. Rule-Based Prompt-Injection Detection
        try:
            prompt_injection_evidence = self.prompt_injection_detector.detect_prompt_injection(webpage_evidence)
        except Exception as e:
            logger.error(f"Prompt injection detection exception for Scan {scan_id}: {e}")
            prompt_injection_evidence = {
                "prompt_injection_detected": False, "error": str(e),
                "matched_patterns": [], "confidence": 0.0
            }

        # 6. AI Analysis (Gatekeeper + Provider Manager)
        # Check total elapsed time before AI
        elapsed = time.time() - start_time
        if elapsed > self.MAX_TOTAL_SECONDS * 0.8:
            logger.warning(f"Near time limit ({elapsed:.1f}s) — skipping AI for Scan {scan_id}")
            ai_evidence = {
                "status": "NOT_RUN",
                "ai_required": False,
                "ai_called": False,
                "reasoning_summary": "Skipped due to time constraints",
                "authoritative": False,
                "timestamp": time.time()
            }
        else:
            try:
                # Build evidence bundle for AI gatekeeper and analysis
                evidence_for_ai = {
                    "webpage": webpage_evidence,
                    "network": network_evidence,
                    "visual": visual_evidence,
                    "threat_intelligence": threat_intel_evidence,
                    "prompt_injection": prompt_injection_evidence,
                }
                ai_evidence = self.ai_analyzer.analyze_with_ai(
                    evidence_for_ai,
                    initial_prediction=initial_prediction,
                    initial_confidence=initial_confidence
                )
            except Exception as e:
                logger.error(f"AI analysis exception for Scan {scan_id}: {e}")
                ai_evidence = {
                    "status": "ERROR",
                    "ai_required": False,
                    "ai_called": False,
                    "error": str(e),
                    "authoritative": False,
                    "timestamp": time.time()
                }

        # Complete evidence bundle
        evidence_data = {
            "scan_id": scan_id,
            "url": url,
            "initial_ml": {
                "class": initial_prediction,
                "confidence": initial_confidence
            },
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

        logger.info(f"Orchestration complete for Scan {scan_id} in {evidence_data['timestamps']['duration_seconds']}s")
        return evidence_data, mongo_doc_id
