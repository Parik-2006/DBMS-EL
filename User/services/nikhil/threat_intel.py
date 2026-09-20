import os
import time
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class ThreatIntelService:
    """
    Provider-independent threat intelligence and local SQL correlation interface.
    Produces EVIDENCE ONLY.
    
    If no external threat intelligence API key is configured (e.g. VIRUSTOTAL_API_KEY),
    the external threat intelligence status is marked 'UNAVAILABLE' without inventing fake results.
    Local database correlation is always queried from the PARI SQL schema.
    """

    @classmethod
    def analyze_threat_intel(cls, url, domain=None, ip=None):
        """
        Query external threat intelligence providers (if configured)
        and local SQL correlation data.
        
        Args:
            url: str target URL
            domain: optional str domain
            ip: optional str resolved IP
            
        Returns:
            dict: Structured threat intelligence evidence
        """
        evidence = {
            "status": "PENDING",
            "provider": None,
            "reputation": "UNKNOWN",
            "external_indicators": [],
            "source": None,
            "local_correlation": {
                "previous_scans_count": 0,
                "known_malicious_in_domain": 0,
                "historical_indicators": [],
                "domain_status": "UNKNOWN"
            },
            "threat_findings": [],
            "error": None,
            "timestamp": time.time()
        }

        # 1. Check External Threat Intelligence Provider (VirusTotal, AlienVault, etc.)
        vt_api_key = os.environ.get('VIRUSTOTAL_API_KEY')
        otx_api_key = os.environ.get('ALIENVAULT_API_KEY')
        
        if vt_api_key:
            evidence["provider"] = "VirusTotal"
            # If a real key is present, we could query VT API here safely with timeout
            evidence["status"] = "CONFIGURED"
        elif otx_api_key:
            evidence["provider"] = "AlienVault OTX"
            evidence["status"] = "CONFIGURED"
        else:
            evidence["status"] = "UNAVAILABLE"
            evidence["source"] = "None (No API Key Configured)"
            evidence["threat_findings"].append("External threat intelligence provider not configured")

        # 2. Local SQL Correlation using existing PARI tables
        try:
            from User.models import Scan, Domain, ThreatIndicator, ScanIndicator, URL

            parsed = urlparse(url if url.startswith(('http://', 'https://')) else f"http://{url}")
            host = domain or parsed.hostname or url

            # Find matching domain in database
            domain_objs = Domain.objects.filter(domain_name__iexact=host)
            if domain_objs.exists():
                domain_obj = domain_objs.first()
                evidence["local_correlation"]["domain_status"] = domain_obj.status
                
                # Check previous scans for this domain
                domain_scans = Scan.objects.filter(url__domain=domain_obj)
                evidence["local_correlation"]["previous_scans_count"] = domain_scans.count()

                # Check malicious scans in this domain
                malicious_scans = domain_scans.filter(
                    prediction__predicted_class__in=['Phishing', 'Malware', 'Defacement']
                ).count()
                evidence["local_correlation"]["known_malicious_in_domain"] = malicious_scans

                if malicious_scans > 0:
                    finding_msg = f"Local Correlation: Domain {host} has {malicious_scans} previously detected malicious scans"
                    evidence["threat_findings"].append(finding_msg)
                    evidence["external_indicators"].append("HISTORICAL_MALICIOUS_DOMAIN")

                # Check historical threat indicators linked to this domain
                related_indicators = ThreatIndicator.objects.filter(
                    scanindicator__scan__in=domain_scans
                ).distinct()[:10]
                
                for ind in related_indicators:
                    evidence["local_correlation"]["historical_indicators"].append({
                        "type": ind.indicator_type,
                        "value": ind.indicator_value,
                        "severity": ind.severity
                    })
                    evidence["external_indicators"].append(f"{ind.indicator_type}:{ind.indicator_value}")

        except Exception as e:
            logger.warning(f"Error checking local correlation: {e}")
            evidence["local_correlation"]["error"] = str(e)

        return evidence
