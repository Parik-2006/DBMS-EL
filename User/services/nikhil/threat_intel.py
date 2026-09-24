"""
Threat Intelligence Service for Nikhil Fallback.
Integrates Free-Only external intelligence (ThreatFox, URLhaus, AbuseIPDB)
with Local SQL Correlation and Trusted Domain Intelligence.
Produces EVIDENCE ONLY — provider failures are fully isolated.
"""
import os
import time
import logging
from urllib.parse import urlparse

from User.services.nikhil.free_only_guard import FreeOnlyGuard
from User.services.nikhil.threatfox_provider import ThreatFoxProvider
from User.services.nikhil.urlhaus_provider import URLhausProvider
from User.services.nikhil.abuseipdb_provider import AbuseIPDBProvider
from User.services.nikhil.trusted_domains import TrustedDomainService

logger = logging.getLogger(__name__)


class class_or_instance_method:
    """Descriptor enabling a method to be called on either a class or an instance."""
    def __init__(self, fn):
        self.fn = fn

    def __get__(self, instance, owner):
        if instance is None:
            def class_wrapper(*args, **kwargs):
                return self.fn(owner(), *args, **kwargs)
            return class_wrapper
        def instance_wrapper(*args, **kwargs):
            return self.fn(instance, *args, **kwargs)
        return instance_wrapper


class ThreatIntelService:
    """
    Provider-independent, free-only threat intelligence collector.
    Coordinates:
      1. Local SQL correlation
      2. Trusted domain intelligence
      3. ThreatFox Community API (exact IOC lookup)
      4. URLhaus Community API (malware URL/host lookup)
      5. AbuseIPDB API (public IP reputation)
    """

    def __init__(self, threatfox=None, urlhaus=None, abuseipdb=None, trusted_domains=None):
        self.threatfox = threatfox or ThreatFoxProvider()
        self.urlhaus = urlhaus or URLhausProvider()
        self.abuseipdb = abuseipdb or AbuseIPDBProvider()
        self.trusted_domains = trusted_domains or TrustedDomainService()

    @class_or_instance_method
    def analyze_threat_intel(self, url: str, domain: str = None, ip: str = None) -> dict:
        """
        Execute deterministic, targeted threat intelligence correlation.

        Args:
            url: str target URL
            domain: optional str domain / host
            ip: optional str resolved IP address

        Returns:
            dict: Structured, normalized threat intelligence evidence
        """
        start_time = time.time()

        parsed = urlparse(url if url.startswith(('http://', 'https://')) else f"http://{url}")
        host = domain or parsed.hostname or url

        # Initialize base evidence schema
        evidence = {
            "status": "PENDING",
            "provider": "Free-Only Threat Intelligence (ThreatFox, URLhaus, AbuseIPDB, SQL)",
            "reputation": "UNKNOWN",
            "external_indicators": [],
            "indicators": [],
            "threat_findings": [],
            "evidence": [],
            "limitations": [],
            "sources": {
                "local_sql": {
                    "status": "PENDING",
                    "previous_scans_count": 0,
                    "known_malicious_in_domain": 0,
                    "historical_indicators": [],
                    "domain_status": "UNKNOWN"
                },
                "trusted_domain": {
                    "status": "PENDING",
                    "is_known": False,
                    "category": None,
                    "confidence": 0.0
                },
                "threatfox": {
                    "status": "NOT_RUN",
                    "hits": 0,
                    "matches": []
                },
                "urlhaus": {
                    "status": "NOT_RUN",
                    "hits": 0,
                    "threat": None
                },
                "abuseipdb": {
                    "status": "NOT_RUN",
                    "abuse_confidence_score": 0,
                    "total_reports": 0
                }
            },
            "summary": {
                "known_malicious_ioc": False,
                "known_malware_url": False,
                "ip_abuse_score": 0,
                "positive_hits": 0,
                "negative_hits": 0,
                "sources_available": 0,
                "sources_failed": 0,
                "external_ti_status": "UNAVAILABLE",
                "threat_intel_ui_summary": "Initializing"
            },
            "local_correlation": {},  # backwards-compatibility
            "error": None,
            "timestamp": start_time
        }

        # -------------------------------------------------------------
        # 1. Local SQL Correlation (Always executed)
        # -------------------------------------------------------------
        try:
            sql_data = self._check_local_sql(host, url)
            evidence["sources"]["local_sql"] = sql_data
            evidence["local_correlation"] = sql_data

            if sql_data.get("known_malicious_in_domain", 0) > 0:
                count = sql_data["known_malicious_in_domain"]
                msg = f"Local SQL Correlation: Domain {host} has {count} previously detected malicious scans"
                evidence["threat_findings"].append(msg)
                evidence["evidence"].append(msg)
                evidence["external_indicators"].append("HISTORICAL_MALICIOUS_DOMAIN")
                evidence["indicators"].append(f"DOMAIN:{host}")

            for ind in sql_data.get("historical_indicators", []):
                evidence["external_indicators"].append(f"{ind.get('type')}:{ind.get('value')}")
                evidence["indicators"].append(f"{ind.get('type', 'OTHER')}:{ind.get('value')}")
        except Exception as e:
            logger.warning(f"Local SQL correlation exception: {e}")
            evidence["sources"]["local_sql"]["status"] = "ERROR"
            evidence["sources"]["local_sql"]["error"] = str(e)

        # -------------------------------------------------------------
        # 2. Trusted Domain Intelligence (Always executed)
        # -------------------------------------------------------------
        try:
            td_data = self.trusted_domains.lookup_domain(url)
            evidence["trusted_domain"] = td_data
            evidence["sources"]["trusted_domain"] = {
                "status": "SUCCESS" if td_data.get("is_known") else "NO_MATCH",
                "is_known": td_data.get("is_known", False),
                "category": td_data.get("category"),
                "organization": td_data.get("organization"),
                "verified": td_data.get("verified", False),
                "confidence": td_data.get("confidence", 0.0),
                "evidence_type": td_data.get("evidence_type")
            }
            if td_data.get("is_known"):
                evidence["evidence"].append(
                    f"Trusted Domain: Category {td_data.get('category')} (domain: {td_data.get('domain')}, verified: {td_data.get('verified', False)})"
                )
        except Exception as e:
            logger.warning(f"Trusted domain intelligence exception: {e}")
            evidence["sources"]["trusted_domain"]["status"] = "ERROR"
            evidence["trusted_domain"] = {"is_known": False, "verified": False, "evidence_type": "ERROR"}

        try:
            evidence["url_features"] = self.trusted_domains.extract_url_features(url)
        except Exception as e:
            logger.warning(f"URL features extraction exception: {e}")
            evidence["url_features"] = {"error": str(e)}

        # -------------------------------------------------------------
        # 3. Check Free-Only Policy & Commercial Provider Guard
        # -------------------------------------------------------------
        free_only = FreeOnlyGuard.is_free_only()
        allow_paid = FreeOnlyGuard.allow_paid_providers()

        # Reject any accidental commercial providers (e.g. VirusTotal, OTX)
        vt_key = os.environ.get("VIRUSTOTAL_API_KEY")
        otx_key = os.environ.get("ALIENVAULT_API_KEY")
        if (vt_key or otx_key) and (free_only and not allow_paid):
            logger.info("[TI] Commercial keys detected in environment but BLOCKED by Free-Only policy.")
            evidence["limitations"].append("Commercial TI providers (VirusTotal/OTX) blocked under Free-Only policy")

        # -------------------------------------------------------------
        # 4. ThreatFox Community API (Domain, URL, and Public IP)
        # -------------------------------------------------------------
        tf_status = "NOT_RUN"
        try:
            # Query domain first
            if host and not host.replace('.', '').isdigit():
                tf_result = self.threatfox.lookup_ioc(host, exact_match=True)
                tf_status = tf_result.get("status", "ERROR")
                evidence["sources"]["threatfox"] = tf_result

                if tf_status == "SUCCESS" and tf_result.get("hits", 0) > 0:
                    evidence["summary"]["known_malicious_ioc"] = True
                    for m in tf_result.get("matches", []):
                        ioc_val = m.get("ioc", host)
                        t_type = m.get("threat_type", "malware")
                        evidence["threat_findings"].append(
                            f"ThreatFox: Malicious IOC found ({ioc_val}, type: {t_type}, malware: {m.get('malware_printable')})"
                        )
                        evidence["evidence"].append(f"ThreatFox IOC: {ioc_val} ({t_type})")
                        evidence["external_indicators"].append(f"THREATFOX_IOC:{ioc_val}")
                        evidence["indicators"].append(f"DOMAIN:{ioc_val}")

            # If resolved public IP is available and domain had no hit, query ThreatFox for IP
            if ip and not evidence["summary"]["known_malicious_ioc"] and self.abuseipdb.is_public_ip(ip):
                tf_ip_result = self.threatfox.lookup_ioc(ip, exact_match=True)
                if tf_ip_result.get("status") == "SUCCESS" and tf_ip_result.get("hits", 0) > 0:
                    evidence["summary"]["known_malicious_ioc"] = True
                    evidence["sources"]["threatfox"] = tf_ip_result
                    tf_status = "SUCCESS"
                    for m in tf_ip_result.get("matches", []):
                        evidence["threat_findings"].append(
                            f"ThreatFox: Malicious IP IOC ({m.get('ioc', ip)}, type: {m.get('threat_type')})"
                        )
                        evidence["evidence"].append(f"ThreatFox IP IOC: {m.get('ioc', ip)}")
                        evidence["external_indicators"].append(f"THREATFOX_IP:{ip}")
                        evidence["indicators"].append(f"IP_ADDRESS:{ip}")
        except Exception as e:
            logger.error(f"ThreatFox query exception: {e}")
            tf_status = "ERROR"
            evidence["sources"]["threatfox"] = {"status": "ERROR", "error": str(e), "hits": 0}

        # -------------------------------------------------------------
        # 5. URLhaus Community API (URL and Host)
        # -------------------------------------------------------------
        uh_status = "NOT_RUN"
        try:
            # Query URL first
            uh_result = self.urlhaus.lookup_url(url)
            uh_status = uh_result.get("status", "ERROR")

            # If no match on URL, check host
            if uh_status == "NO_MATCH" and host:
                uh_host_result = self.urlhaus.lookup_host(host)
                if uh_host_result.get("status") == "SUCCESS":
                    uh_result = uh_host_result
                    uh_status = "SUCCESS"
                elif uh_host_result.get("status") in ("RATE_LIMITED", "AUTH_ERROR", "UNAVAILABLE"):
                    uh_status = uh_host_result.get("status")

            evidence["sources"]["urlhaus"] = uh_result

            if uh_status == "SUCCESS" and uh_result.get("hits", 0) > 0:
                evidence["summary"]["known_malware_url"] = True
                threat_desc = uh_result.get("threat") or "malware_download"
                status_desc = uh_result.get("url_status") or "active"
                evidence["threat_findings"].append(
                    f"URLhaus: Malware distribution infrastructure detected (threat: {threat_desc}, status: {status_desc})"
                )
                evidence["evidence"].append(f"URLhaus malware hit: {threat_desc} ({status_desc})")
                evidence["external_indicators"].append(f"URLHAUS_MALWARE:{host}")
                evidence["indicators"].append(f"OTHER:URLhaus malware infrastructure ({threat_desc})")
        except Exception as e:
            logger.error(f"URLhaus query exception: {e}")
            uh_status = "ERROR"
            evidence["sources"]["urlhaus"] = {"status": "ERROR", "error": str(e), "hits": 0}

        # -------------------------------------------------------------
        # 6. AbuseIPDB API (Public IP Reputation)
        # -------------------------------------------------------------
        aip_status = "NOT_RUN"
        try:
            if ip:
                if self.abuseipdb.is_public_ip(ip):
                    aip_result = self.abuseipdb.check_ip(ip)
                    aip_status = aip_result.get("status", "ERROR")
                    evidence["sources"]["abuseipdb"] = aip_result

                    score = aip_result.get("abuse_confidence_score", 0)
                    evidence["summary"]["ip_abuse_score"] = score

                    if score >= 25:
                        reports = aip_result.get("total_reports", 0)
                        evidence["threat_findings"].append(
                            f"AbuseIPDB: High abuse confidence score ({score}%) with {reports} reports for IP {ip}"
                        )
                        evidence["evidence"].append(f"AbuseIPDB IP {ip} score: {score}% ({reports} reports)")
                        evidence["external_indicators"].append(f"ABUSEIPDB_SCORE:{score}")
                        evidence["indicators"].append(f"REPUTATION:AbuseIPDB score {score}% for {ip}")
                else:
                    evidence["sources"]["abuseipdb"] = {
                        "status": "SKIPPED_PRIVATE_IP",
                        "abuse_confidence_score": 0,
                        "total_reports": 0,
                        "message": "Private or local IP not submitted to external reputation API"
                    }
                    aip_status = "SKIPPED_PRIVATE_IP"
            else:
                evidence["sources"]["abuseipdb"] = {
                    "status": "NOT_RUN",
                    "abuse_confidence_score": 0,
                    "total_reports": 0,
                    "message": "No IP address resolved"
                }
                aip_status = "NOT_RUN"
        except Exception as e:
            logger.error(f"AbuseIPDB query exception: {e}")
            aip_status = "ERROR"
            evidence["sources"]["abuseipdb"] = {"status": "ERROR", "error": str(e)}

        # -------------------------------------------------------------
        # 7. Multi-Source Result Normalization and Synthesis
        # -------------------------------------------------------------
        ext_sources = [
            ("ThreatFox", tf_status, evidence["sources"]["threatfox"]),
            ("URLhaus", uh_status, evidence["sources"]["urlhaus"]),
            ("AbuseIPDB", aip_status, evidence["sources"]["abuseipdb"]),
        ]

        sources_available = 0
        sources_failed = 0
        positive_hits = 0
        negative_hits = 0

        for name, st, data in ext_sources:
            if st in ("SUCCESS", "NO_MATCH", "SKIPPED_PRIVATE_IP"):
                sources_available += 1
                if st == "SUCCESS" and (data.get("hits", 0) > 0 or data.get("abuse_confidence_score", 0) >= 25):
                    positive_hits += 1
                else:
                    negative_hits += 1
            elif st in ("UNAVAILABLE", "AUTH_ERROR", "RATE_LIMITED", "TIMEOUT", "ERROR", "CONFIGURATION_BLOCKED"):
                sources_failed += 1

        evidence["summary"]["positive_hits"] = positive_hits
        evidence["summary"]["negative_hits"] = negative_hits
        evidence["summary"]["sources_available"] = sources_available
        evidence["summary"]["sources_failed"] = sources_failed

        # Determine overall external TI status
        if sources_available > 0 and positive_hits > 0:
            overall_status = "SUCCESS"
            reputation = "SUSPICIOUS" if positive_hits == 1 else "MALICIOUS"
        elif sources_available > 0 and sources_failed == 0:
            overall_status = "SUCCESS"
            reputation = "CLEAN" if evidence["sources"]["trusted_domain"].get("is_known") else "NEUTRAL"
        elif sources_available > 0 and sources_failed > 0:
            overall_status = "PARTIAL"
            reputation = "NEUTRAL"
        elif any(st == "RATE_LIMITED" for _, st, _ in ext_sources):
            overall_status = "RATE_LIMITED"
            reputation = "UNKNOWN"
        else:
            overall_status = "UNAVAILABLE"
            reputation = "UNKNOWN"

        evidence["status"] = overall_status
        evidence["reputation"] = reputation
        evidence["summary"]["external_ti_status"] = overall_status

        # Generate concise UI summary string
        if overall_status == "SUCCESS":
            if positive_hits > 0:
                ui_summary = f"SUCCESS · {sources_available} sources checked · {positive_hits} malicious indicator(s) found"
            else:
                ui_summary = f"SUCCESS · {sources_available} sources checked · No malicious indicators found in checked sources"
        elif overall_status == "PARTIAL":
            statuses = [f"{n}: {st}" for n, st, _ in ext_sources if st not in ("NOT_RUN", "SKIPPED_PRIVATE_IP")]
            ui_summary = f"PARTIAL · {', '.join(statuses)}"
        elif overall_status == "RATE_LIMITED":
            ui_summary = "RATE_LIMITED · External TI rate limit reached · Local SQL/Domain correlation active"
        else:
            ui_summary = "UNAVAILABLE · External TI sources unavailable · Local SQL/Domain correlation active"

        evidence["summary"]["threat_intel_ui_summary"] = ui_summary

        if overall_status in ("UNAVAILABLE", "RATE_LIMITED"):
            evidence["limitations"].append(
                f"External threat intelligence {overall_status.lower()}; relying on local correlation, network, and DOM analysis."
            )

        return evidence

    @staticmethod
    def _check_local_sql(host: str, url: str) -> dict:
        """
        Local SQL Correlation using existing PARI tables.
        """
        sql_data = {
            "status": "SUCCESS",
            "previous_scans_count": 0,
            "known_malicious_in_domain": 0,
            "historical_indicators": [],
            "domain_status": "UNKNOWN"
        }
        try:
            from User.models import Scan, Domain, ThreatIndicator, ScanIndicator
            domain_objs = Domain.objects.filter(domain_name__iexact=host)
            if domain_objs.exists():
                domain_obj = domain_objs.first()
                sql_data["domain_status"] = domain_obj.status
                
                domain_scans = Scan.objects.filter(url__domain=domain_obj)
                sql_data["previous_scans_count"] = domain_scans.count()

                malicious_scans = domain_scans.filter(
                    prediction__predicted_class__in=['Phishing', 'Malware', 'Defacement']
                ).count()
                sql_data["known_malicious_in_domain"] = malicious_scans

                related_indicators = ThreatIndicator.objects.filter(
                    scanindicator__scan__in=domain_scans
                ).distinct()[:10]
                
                for ind in related_indicators:
                    sql_data["historical_indicators"].append({
                        "type": ind.indicator_type,
                        "value": ind.indicator_value,
                        "severity": ind.severity
                    })
        except Exception as e:
            logger.warning(f"Error checking local SQL correlation: {e}")
            sql_data["status"] = "ERROR"
            sql_data["error"] = str(e)

        return sql_data
