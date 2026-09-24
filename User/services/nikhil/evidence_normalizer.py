"""
Evidence Normalizer — Standardizes output from all collectors.
"""
import time
import logging

logger = logging.getLogger(__name__)

VALID_STATUSES = {"SUCCESS", "UNAVAILABLE", "TIMEOUT", "ERROR", "NOT_RUN", "SKIPPED", "FAILED", "PENDING"}


class EvidenceNormalizer:
    """
    Normalizes collector outputs to a standard structure.

    IMPORTANT: UNAVAILABLE != CLEAN, NOT_RUN != CLEAN, ERROR != CLEAN
    """

    @classmethod
    def normalize(cls, collector_name, raw_evidence):
        """
        Normalize raw evidence into the standard format.

        Args:
            collector_name: str identifying the collector
            raw_evidence: dict raw output from a collector

        Returns:
            dict: {
                "collector": str,
                "status": str,
                "confidence": float,
                "evidence": list,
                "indicators": list,
                "errors": list,
                "metadata": dict,
                "timestamp": str
            }
        """
        if not isinstance(raw_evidence, dict):
            return cls._empty(collector_name, "ERROR", ["Raw evidence is not a dict"])

        status = raw_evidence.get("status", "NOT_RUN")
        if status not in VALID_STATUSES:
            status = "ERROR"

        indicators = raw_evidence.get("indicators", [])
        if not isinstance(indicators, list):
            indicators = []

        errors = []
        if raw_evidence.get("error"):
            errors.append(str(raw_evidence["error"]))

        evidence = []
        findings = raw_evidence.get("findings", []) or raw_evidence.get("network_findings", []) or raw_evidence.get("visual_findings", []) or raw_evidence.get("threat_findings", [])
        if isinstance(findings, list):
            evidence = [str(f)[:300] for f in findings[:20]]

        # Collector-specific metadata extraction
        metadata = {}
        if collector_name == "webpage":
            metadata = {
                "title": raw_evidence.get("title", ""),
                "form_count": raw_evidence.get("page_structure", {}).get("num_forms", 0),
                "has_password_form": "PASSWORD_FORM" in indicators,
                "cross_domain_forms": "CROSS_DOMAIN_FORM" in indicators,
                "http_status": raw_evidence.get("http_status"),
                "content_type": raw_evidence.get("content_type", ""),
            }
        elif collector_name == "network":
            ssl_info = raw_evidence.get("ssl", {})
            metadata = {
                "domain": raw_evidence.get("domain", ""),
                "ip": raw_evidence.get("ip_resolution", {}).get("primary_ip"),
                "reverse_dns": raw_evidence.get("ip_resolution", {}).get("reverse_dns"),
                "https": ssl_info.get("is_https", False),
                "tls_valid": ssl_info.get("verified", False),
                "certificate_valid": ssl_info.get("verified", False) and not ssl_info.get("is_expired", False),
                "is_ip_address": raw_evidence.get("is_ip_address", False),
            }
        elif collector_name == "visual":
            metadata = {
                "screenshot_reference": raw_evidence.get("screenshot_reference"),
                "title": raw_evidence.get("title", ""),
            }
        elif collector_name == "threat_intelligence":
            sources = raw_evidence.get("sources", {})
            summary = raw_evidence.get("summary", {})
            metadata = {
                "provider": raw_evidence.get("provider"),
                "reputation": raw_evidence.get("reputation", "UNKNOWN"),
                "local_correlation": raw_evidence.get("local_correlation", {}),
                "summary": summary,
                "threatfox_status": sources.get("threatfox", {}).get("status", "NOT_RUN"),
                "threatfox_hits": sources.get("threatfox", {}).get("hits", 0),
                "urlhaus_status": sources.get("urlhaus", {}).get("status", "NOT_RUN"),
                "urlhaus_hits": sources.get("urlhaus", {}).get("hits", 0),
                "abuseipdb_status": sources.get("abuseipdb", {}).get("status", "NOT_RUN"),
                "abuseipdb_score": sources.get("abuseipdb", {}).get("abuse_confidence_score", 0),
                "abuseipdb_reports": sources.get("abuseipdb", {}).get("total_reports", 0),
                "trusted_domain_category": sources.get("trusted_domain", {}).get("category"),
                "trusted_domain_known": sources.get("trusted_domain", {}).get("is_known", False),
                "ui_summary": summary.get("threat_intel_ui_summary", "")
            }
        elif collector_name == "prompt_injection":
            metadata = {
                "detected": raw_evidence.get("prompt_injection_detected", False),
                "severity": "HIGH" if raw_evidence.get("prompt_injection_detected") else "NONE",
                "categories": raw_evidence.get("matched_patterns", []),
                "confidence": raw_evidence.get("confidence", 0.0),
            }
        elif collector_name == "ai":
            metadata = {
                "provider": raw_evidence.get("provider"),
                "model": raw_evidence.get("model"),
                "assessment": raw_evidence.get("assessment"),
                "ai_confidence": raw_evidence.get("confidence", 0.0),
            }

        return {
            "collector": collector_name,
            "status": status,
            "confidence": 0.0,  # Individual collector confidence — calculated by corroboration
            "evidence": evidence,
            "indicators": indicators,
            "errors": errors,
            "metadata": metadata,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ")
        }

    @classmethod
    def _empty(cls, collector_name, status="NOT_RUN", errors=None):
        return {
            "collector": collector_name,
            "status": status,
            "confidence": 0.0,
            "evidence": [],
            "indicators": [],
            "errors": errors or [],
            "metadata": {},
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ")
        }

    @classmethod
    def build_ai_input(cls, initial_ml, normalized_evidence):
        """
        Build compact, safe AI input from normalized evidence.
        Never includes secrets, keys, cookies, or raw HTML.

        Args:
            initial_ml: dict with initial ML prediction info
            normalized_evidence: dict of normalized collector outputs

        Returns:
            dict: Safe, bounded evidence payload for AI
        """
        import os
        max_snippets = int(os.environ.get('MAX_AI_SNIPPETS', '8'))

        webpage_norm = normalized_evidence.get("webpage", {})
        network_norm = normalized_evidence.get("network", {})
        visual_norm = normalized_evidence.get("visual", {})
        threat_norm = normalized_evidence.get("threat_intelligence", {})
        prompt_norm = normalized_evidence.get("prompt_injection", {})

        return {
            "initial_ml": {
                "class": initial_ml.get("class", "Unknown"),
                "confidence": initial_ml.get("confidence", 0.0),
            },
            "webpage": {
                "status": webpage_norm.get("status", "NOT_RUN"),
                "title": webpage_norm.get("metadata", {}).get("title", "")[:200],
                "forms": webpage_norm.get("metadata", {}).get("form_count", 0),
                "credential_inputs": 1 if webpage_norm.get("metadata", {}).get("has_password_form") else 0,
                "cross_domain_forms": 1 if webpage_norm.get("metadata", {}).get("cross_domain_forms") else 0,
                "indicators": webpage_norm.get("indicators", [])[:max_snippets],
                "snippets": webpage_norm.get("evidence", [])[:max_snippets],
            },
            "network": {
                "status": network_norm.get("status", "NOT_RUN"),
                "https": network_norm.get("metadata", {}).get("https", False),
                "tls_valid": network_norm.get("metadata", {}).get("tls_valid", False),
                "certificate_valid": network_norm.get("metadata", {}).get("certificate_valid", False),
                "ip": network_norm.get("metadata", {}).get("ip"),
                "reverse_dns": network_norm.get("metadata", {}).get("reverse_dns"),
            },
            "threat_intelligence": {
                "status": threat_norm.get("status", "NOT_RUN"),
                "reputation": threat_norm.get("metadata", {}).get("reputation", "UNKNOWN"),
                "threatfox": {
                    "status": threat_norm.get("metadata", {}).get("threatfox_status", "NOT_RUN"),
                    "hits": threat_norm.get("metadata", {}).get("threatfox_hits", 0),
                },
                "urlhaus": {
                    "status": threat_norm.get("metadata", {}).get("urlhaus_status", "NOT_RUN"),
                    "hits": threat_norm.get("metadata", {}).get("urlhaus_hits", 0),
                },
                "abuseipdb": {
                    "status": threat_norm.get("metadata", {}).get("abuseipdb_status", "NOT_RUN"),
                    "abuse_confidence_score": threat_norm.get("metadata", {}).get("abuseipdb_score", 0),
                    "reports": threat_norm.get("metadata", {}).get("abuseipdb_reports", 0),
                },
                "trusted_domain": {
                    "category": threat_norm.get("metadata", {}).get("trusted_domain_category"),
                    "verified": threat_norm.get("metadata", {}).get("trusted_domain_known", False),
                },
                "known_indicators": threat_norm.get("indicators", [])[:5],
            },
            "prompt_injection": {
                "detected": prompt_norm.get("metadata", {}).get("detected", False),
                "severity": prompt_norm.get("metadata", {}).get("severity", "NONE"),
                "categories": prompt_norm.get("metadata", {}).get("categories", [])[:5],
            },
            "visual": {
                "status": visual_norm.get("status", "NOT_RUN"),
                "findings": visual_norm.get("evidence", [])[:5],
            }
        }
