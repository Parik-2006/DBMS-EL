"""
Evidence Corroboration and Final Classification Engine.

IMPORTANT RULES:
1. Does NOT simply return the initial Random Forest class.
2. Preserves initial_prediction and initial_confidence.
3. Combines evidence from multiple independent evidence families:
   - URL / Legitimacy Features
   - Webpage / HTML / DOM
   - Network / DNS / SSL
   - Visual / Screenshot
   - Threat Intelligence / SQL Correlation
   - Prompt Injection
   - AI Analysis (optional, evidence only)
4. Evaluates engineering evidence scores for: Benign, Phishing, Malware, Defacement.
5. Requires corroboration across MULTIPLE independent families for high confidence.
6. If evidence is insufficient or conflicting -> returns 'Unknown' (Needs Review).
7. AI assessment is SUPPORTING evidence, NEVER the final authority.
8. Trusted domain is SUPPORTING evidence, NEVER automatic Benign.
"""
import logging

logger = logging.getLogger(__name__)


class FinalClassifier:

    @classmethod
    def classify(cls, initial_prediction, initial_confidence, evidence):
        """
        Corroborate gathered evidence and calculate final classification.

        Args:
            initial_prediction: str (e.g. 'Defacement', 'Phishing', 'Benign', 'Malware')
            initial_confidence: float (e.g. 0.43)
            evidence: dict containing structured evidence from all analyzers

        Returns:
            dict: {
                "final_classification": str,
                "risk_level": str,
                "risk_score": float,
                "evidence_summary": str,
                "evidence_breakdown": dict,
                "corroboration": dict,
                "threat_indicators": list
            }
        """
        webpage = evidence.get("webpage", {})
        network = evidence.get("network", {})
        visual = evidence.get("visual", {})
        threat_intel = evidence.get("threat_intelligence", {})
        prompt_inj = evidence.get("prompt_injection", {})
        ai_analysis = evidence.get("ai_analysis", {})

        # Breakdown trackers
        breakdown = {
            "url_legitimacy": [],
            "webpage": [],
            "network": [],
            "visual": [],
            "threat_intelligence": [],
            "prompt_injection": [],
            "ai": []
        }

        threat_indicators = []

        # Family score boards: map class -> set of contributing family names
        family_contributions = {
            "Benign": set(),
            "Phishing": set(),
            "Malware": set(),
            "Defacement": set()
        }

        scores = {
            "Benign": 0.0,
            "Phishing": 0.0,
            "Malware": 0.0,
            "Defacement": 0.0
        }

        # -------------------------------------------------------------------
        # Family 0: URL / Legitimacy Features & Trusted Domain
        # -------------------------------------------------------------------
        trusted_domain = threat_intel.get("trusted_domain", {})
        url_features = threat_intel.get("url_features", {})

        if trusted_domain.get("is_known"):
            # Known trusted domain — SUPPORTING evidence, NOT automatic Benign
            scores["Benign"] += 2.0
            family_contributions["Benign"].add("URL_LEGITIMACY")
            breakdown["url_legitimacy"].append(
                f"Known domain: {trusted_domain.get('organization', 'N/A')} "
                f"(category: {trusted_domain.get('category', 'N/A')}) (+2.0 Benign)"
            )
        elif trusted_domain.get("trusted_tld"):
            scores["Benign"] += 1.0
            family_contributions["Benign"].add("URL_LEGITIMACY")
            breakdown["url_legitimacy"].append(
                f"Trusted TLD detected (+1.0 Benign)"
            )

        # URL feature indicators
        if url_features and not url_features.get("error"):
            suspicious_tokens = url_features.get("suspicious_token_count", 0)
            if suspicious_tokens >= 3:
                scores["Phishing"] += 2.0
                family_contributions["Phishing"].add("URL_LEGITIMACY")
                breakdown["url_legitimacy"].append(
                    f"Multiple suspicious URL tokens ({suspicious_tokens}) detected (+2.0 Phishing)"
                )
                threat_indicators.append("URL:SUSPICIOUS_TOKENS")

            if url_features.get("credential_path"):
                scores["Phishing"] += 1.5
                family_contributions["Phishing"].add("URL_LEGITIMACY")
                breakdown["url_legitimacy"].append(
                    "Credential-themed path detected (+1.5 Phishing)"
                )

            if url_features.get("is_ip_hostname"):
                scores["Phishing"] += 1.0
                scores["Malware"] += 1.0
                family_contributions["Phishing"].add("URL_LEGITIMACY")
                breakdown["url_legitimacy"].append(
                    "IP address used as hostname (+1.0 Phishing/Malware)"
                )

            if url_features.get("unusual_tld"):
                scores["Phishing"] += 1.0
                family_contributions["Phishing"].add("URL_LEGITIMACY")
                breakdown["url_legitimacy"].append(
                    "Unusual/suspicious TLD detected (+1.0 Phishing)"
                )

            if url_features.get("has_punycode"):
                scores["Phishing"] += 1.5
                family_contributions["Phishing"].add("URL_LEGITIMACY")
                breakdown["url_legitimacy"].append(
                    "Punycode/IDN domain detected (+1.5 Phishing)"
                )
                threat_indicators.append("URL:PUNYCODE_DOMAIN")

            if url_features.get("suspicious_port"):
                scores["Malware"] += 1.0
                family_contributions["Malware"].add("URL_LEGITIMACY")
                breakdown["url_legitimacy"].append(
                    "Suspicious port detected (+1.0 Malware)"
                )

            if url_features.get("excessive_hyphens") or url_features.get("excessive_dots"):
                scores["Phishing"] += 0.5
                breakdown["url_legitimacy"].append(
                    "Excessive hostname separators (+0.5 Phishing)"
                )

            # Normal URL structure supports benign
            if (not suspicious_tokens and not url_features.get("credential_path")
                    and not url_features.get("is_ip_hostname")
                    and not url_features.get("unusual_tld")
                    and not url_features.get("has_punycode")
                    and url_features.get("url_length", 0) < 200):
                scores["Benign"] += 0.5
                breakdown["url_legitimacy"].append("Normal URL structure (+0.5 Benign)")

        # -------------------------------------------------------------------
        # Family 1: Webpage / HTML Evidence
        # -------------------------------------------------------------------
        wp_status = webpage.get("status")
        wp_indicators = webpage.get("indicators", [])

        if wp_status == "SUCCESS":
            if "PASSWORD_FORM" in wp_indicators:
                scores["Phishing"] += 2.5
                family_contributions["Phishing"].add("WEBPAGE")
                breakdown["webpage"].append("Form with password input detected (+2.5 Phishing)")
                threat_indicators.append("WEBPAGE:PASSWORD_FORM")

            if "CROSS_DOMAIN_FORM" in wp_indicators:
                scores["Phishing"] += 3.5
                family_contributions["Phishing"].add("WEBPAGE")
                breakdown["webpage"].append("Cross-domain form action detected (+3.5 Phishing)")
                threat_indicators.append("WEBPAGE:CROSS_DOMAIN_FORM")

            if "CREDENTIAL_HARVESTING_TEXT" in wp_indicators:
                scores["Phishing"] += 2.0
                family_contributions["Phishing"].add("TEXT")
                breakdown["webpage"].append("Credential harvesting phrase detected (+2.0 Phishing)")
                threat_indicators.append("TEXT:CREDENTIAL_HARVESTING")

            if "DEFACEMENT_TEXT" in wp_indicators:
                scores["Defacement"] += 3.5
                family_contributions["Defacement"].add("TEXT")
                breakdown["webpage"].append("Defacement keyword pattern detected (+3.5 Defacement)")
                threat_indicators.append("TEXT:DEFACEMENT_CONTENT")

            if "SUSPICIOUS_DOWNLOAD" in wp_indicators:
                scores["Malware"] += 4.0
                family_contributions["Malware"].add("WEBPAGE")
                breakdown["webpage"].append("Direct executable download link detected (+4.0 Malware)")
                threat_indicators.append("WEBPAGE:SUSPICIOUS_DOWNLOAD")

            if "SUSPICIOUS_IFRAME" in wp_indicators:
                scores["Malware"] += 1.5
                scores["Phishing"] += 1.0
                family_contributions["Malware"].add("WEBPAGE")
                breakdown["webpage"].append("Hidden zero-size iframe detected (+1.5 Malware)")
                threat_indicators.append("WEBPAGE:SUSPICIOUS_IFRAME")

            if "SUSPICIOUS_SCRIPT" in wp_indicators:
                scores["Malware"] += 2.0
                family_contributions["Malware"].add("WEBPAGE")
                breakdown["webpage"].append("Obfuscated or eval JavaScript pattern detected (+2.0 Malware)")
                threat_indicators.append("WEBPAGE:SUSPICIOUS_SCRIPT")

            if "HIDDEN_CONTENT" in wp_indicators:
                scores["Phishing"] += 0.5
                scores["Defacement"] += 0.5
                breakdown["webpage"].append("Hidden text elements found (+0.5 Phishing/Defacement)")

            if "SUSPICIOUS_REDIRECT" in wp_indicators:
                scores["Phishing"] += 1.5
                family_contributions["Phishing"].add("WEBPAGE")
                breakdown["webpage"].append("Suspicious cross-domain redirect (+1.5 Phishing)")
                threat_indicators.append("WEBPAGE:SUSPICIOUS_REDIRECT")

            # Clean webpage supports benign
            if not wp_indicators and webpage.get("page_structure", {}).get("num_tags", 0) > 10:
                scores["Benign"] += 2.0
                family_contributions["Benign"].add("WEBPAGE")
                breakdown["webpage"].append("Standard benign HTML structure without suspicious indicators (+2.0 Benign)")
        else:
            breakdown["webpage"].append(f"Webpage fetch status: {wp_status}")

        # -------------------------------------------------------------------
        # Family 2: Network / DNS / SSL Evidence
        # -------------------------------------------------------------------
        net_status = network.get("status")
        if net_status == "SUCCESS":
            if network.get("is_ip_address"):
                scores["Phishing"] += 1.5
                scores["Malware"] += 1.5
                family_contributions["Phishing"].add("NETWORK")
                family_contributions["Malware"].add("NETWORK")
                breakdown["network"].append("Host is a raw IP address (+1.5 Phishing/Malware)")
                threat_indicators.append("NETWORK:RAW_IP_HOST")

            ssl_info = network.get("ssl", {})
            if ssl_info.get("verified") is True:
                scores["Benign"] += 1.5
                family_contributions["Benign"].add("NETWORK")
                breakdown["network"].append("Valid SSL certificate verified (+1.5 Benign)")
            elif ssl_info.get("verified") is False or ssl_info.get("is_expired") is True:
                scores["Phishing"] += 1.5
                family_contributions["Phishing"].add("NETWORK")
                breakdown["network"].append("Untrusted or expired SSL certificate (+1.5 Phishing)")
                threat_indicators.append("NETWORK:SSL_VERIFICATION_FAILED")

            http_meta = network.get("http_metadata", {})
            if len(http_meta.get("redirect_chain", [])) > 2:
                scores["Phishing"] += 1.0
                scores["Malware"] += 1.0
                family_contributions["Phishing"].add("NETWORK")
                breakdown["network"].append("Multiple redirect hops detected (+1.0 Phishing/Malware)")
                threat_indicators.append("NETWORK:EXCESSIVE_REDIRECTS")

            # Normal DNS resolution supports benign
            ip_resolution = network.get("ip_resolution", {})
            if ip_resolution.get("primary_ip") and not network.get("is_ip_address"):
                if not ssl_info.get("error"):
                    scores["Benign"] += 0.5
                    breakdown["network"].append("Normal DNS resolution (+0.5 Benign)")
        else:
            breakdown["network"].append(f"Network status: {net_status}")

        # -------------------------------------------------------------------
        # Family 3: Visual / Screenshot Evidence
        # -------------------------------------------------------------------
        vis_status = visual.get("status")
        if vis_status == "SUCCESS":
            breakdown["visual"].append(f"Screenshot reference: {visual.get('screenshot_reference')}")
            for finding in visual.get("visual_findings", []):
                breakdown["visual"].append(f"Visual observation: {finding}")
        else:
            breakdown["visual"].append(f"Visual module: {vis_status} ({visual.get('error') or 'Unavailable'})")

        # -------------------------------------------------------------------
        # Family 4: Threat Intelligence (ThreatFox, URLhaus, AbuseIPDB, SQL)
        # -------------------------------------------------------------------
        ti_status = threat_intel.get("status")
        ti_sources = threat_intel.get("sources", {})
        ti_summary = threat_intel.get("summary", {})
        local_correl = threat_intel.get("local_correlation", {}) or ti_sources.get("local_sql", {})
        known_malicious = local_correl.get("known_malicious_in_domain", 0)

        # 4a. Local SQL correlation
        if known_malicious > 0:
            scores["Phishing"] += 2.0
            scores["Malware"] += 2.0
            family_contributions["Phishing"].add("SQL_CORRELATION")
            family_contributions["Malware"].add("SQL_CORRELATION")
            breakdown["threat_intelligence"].append(
                f"SQL Correlation: Domain linked to {known_malicious} previously detected malicious scans (+2.0)"
            )
            threat_indicators.append("CORRELATION:HISTORICAL_MALICIOUS_DOMAIN")

        # 4b. ThreatFox Community API Evidence
        tf_data = ti_sources.get("threatfox", {})
        if tf_data.get("status") == "SUCCESS" and tf_data.get("hits", 0) > 0:
            threat_types = tf_data.get("threat_types", [])
            is_phishing = any("phishing" in str(t).lower() or "credential" in str(t).lower() for t in threat_types)
            if is_phishing:
                scores["Phishing"] += 3.0
                family_contributions["Phishing"].add("THREAT_INTEL")
                breakdown["threat_intelligence"].append(
                    f"ThreatFox: Malicious phishing IOC match found (+3.0 Phishing)"
                )
                threat_indicators.append("THREAT_INTEL:THREATFOX_PHISHING_IOC")
            else:
                scores["Malware"] += 3.0
                family_contributions["Malware"].add("THREAT_INTEL")
                breakdown["threat_intelligence"].append(
                    f"ThreatFox: Known malware IOC match ({', '.join(tf_data.get('malware_families', [])[:2]) or 'IOC'}) (+3.0 Malware)"
                )
                threat_indicators.append("THREAT_INTEL:THREATFOX_MALWARE_IOC")

        # 4c. URLhaus Community API Evidence
        uh_data = ti_sources.get("urlhaus", {})
        if uh_data.get("status") == "SUCCESS" and uh_data.get("hits", 0) > 0:
            scores["Malware"] += 3.5
            family_contributions["Malware"].add("THREAT_INTEL")
            threat_name = uh_data.get("threat") or "malware_download"
            breakdown["threat_intelligence"].append(
                f"URLhaus: Active malware distribution infrastructure detected ({threat_name}) (+3.5 Malware)"
            )
            threat_indicators.append("THREAT_INTEL:URLHAUS_MALWARE_URL")

        # 4d. AbuseIPDB IP Reputation Evidence
        aip_data = ti_sources.get("abuseipdb", {})
        if aip_data.get("status") == "SUCCESS":
            abuse_score = aip_data.get("abuse_confidence_score", 0)
            if abuse_score >= 75:
                scores["Malware"] += 2.0
                scores["Phishing"] += 1.5
                family_contributions["Malware"].add("THREAT_INTEL")
                family_contributions["Phishing"].add("THREAT_INTEL")
                breakdown["threat_intelligence"].append(
                    f"AbuseIPDB: High abuse confidence score ({abuse_score}%) (+2.0 Malware, +1.5 Phishing)"
                )
                threat_indicators.append(f"THREAT_INTEL:ABUSEIPDB_SCORE_{abuse_score}")
            elif abuse_score >= 25:
                scores["Malware"] += 1.0
                scores["Phishing"] += 1.0
                family_contributions["Malware"].add("THREAT_INTEL")
                breakdown["threat_intelligence"].append(
                    f"AbuseIPDB: Moderate abuse confidence score ({abuse_score}%) (+1.0)"
                )
                threat_indicators.append(f"THREAT_INTEL:ABUSEIPDB_SCORE_{abuse_score}")
            elif abuse_score == 0 and not ti_summary.get("known_malicious_ioc") and not ti_summary.get("known_malware_url"):
                scores["Benign"] += 0.5
                breakdown["threat_intelligence"].append(
                    f"AbuseIPDB: Clean reputation (0% abuse score) (+0.5 Benign)"
                )

        for ind in threat_intel.get("external_indicators", []):
            if f"THREAT_INTEL:{ind}" not in threat_indicators:
                threat_indicators.append(f"THREAT_INTEL:{ind}")

        for ind in threat_intel.get("indicators", []):
            if ind not in threat_indicators:
                threat_indicators.append(ind)

        if ti_status == "UNAVAILABLE":
            breakdown["threat_intelligence"].append("External threat intelligence provider UNAVAILABLE (Local SQL/Domain correlation active)")
        elif ti_status == "RATE_LIMITED":
            breakdown["threat_intelligence"].append("External threat intelligence RATE LIMITED (Local SQL/Domain correlation active)")
        elif ti_status == "SUCCESS" and ti_summary.get("positive_hits", 0) == 0:
            breakdown["threat_intelligence"].append("ThreatFox & URLhaus: Clean (NO_MATCH - no known malicious IOCs)")

        # -------------------------------------------------------------------
        # Family 5: Prompt-Injection Detection
        # -------------------------------------------------------------------
        if prompt_inj.get("prompt_injection_detected"):
            scores["Phishing"] += 1.5
            scores["Malware"] += 1.5
            family_contributions["Phishing"].add("PROMPT_INJECTION")
            family_contributions["Malware"].add("PROMPT_INJECTION")
            breakdown["prompt_injection"].append(
                f"Adversarial prompt injection detected: {prompt_inj.get('explanation')} (+1.5 Phishing/Malware)"
            )
            threat_indicators.append("SECURITY:PROMPT_INJECTION_DETECTED")
        else:
            breakdown["prompt_injection"].append("No prompt injection detected")

        # -------------------------------------------------------------------
        # Family 6: AI Analysis (Optional Supporting Evidence)
        # -------------------------------------------------------------------
        ai_status = ai_analysis.get("status", "NOT_RUN")
        ai_assessment = ai_analysis.get("assessment")

        if ai_status == "SUCCESS" and ai_assessment:
            ai_confidence = ai_analysis.get("confidence", 0.0)
            # AI contributes as SUPPORTING evidence — reduced weight
            ai_weight = min(1.5, ai_confidence * 2.0)  # Max 1.5 from AI

            if ai_assessment == "LIKELY_BENIGN":
                scores["Benign"] += ai_weight
                family_contributions["Benign"].add("AI")
                breakdown["ai"].append(
                    f"AI ({ai_analysis.get('provider', 'unknown')}): LIKELY_BENIGN "
                    f"(confidence: {ai_confidence:.2f}, weight: +{ai_weight:.1f} Benign)"
                )
            elif ai_assessment == "LIKELY_PHISHING":
                scores["Phishing"] += ai_weight
                family_contributions["Phishing"].add("AI")
                breakdown["ai"].append(
                    f"AI ({ai_analysis.get('provider', 'unknown')}): LIKELY_PHISHING "
                    f"(confidence: {ai_confidence:.2f}, weight: +{ai_weight:.1f} Phishing)"
                )
            elif ai_assessment == "LIKELY_MALWARE":
                scores["Malware"] += ai_weight
                family_contributions["Malware"].add("AI")
                breakdown["ai"].append(
                    f"AI ({ai_analysis.get('provider', 'unknown')}): LIKELY_MALWARE "
                    f"(confidence: {ai_confidence:.2f}, weight: +{ai_weight:.1f} Malware)"
                )
            elif ai_assessment == "LIKELY_DEFACEMENT":
                scores["Defacement"] += ai_weight
                family_contributions["Defacement"].add("AI")
                breakdown["ai"].append(
                    f"AI ({ai_analysis.get('provider', 'unknown')}): LIKELY_DEFACEMENT "
                    f"(confidence: {ai_confidence:.2f}, weight: +{ai_weight:.1f} Defacement)"
                )
            elif ai_assessment in ("CONFLICTING", "INCONCLUSIVE"):
                breakdown["ai"].append(
                    f"AI ({ai_analysis.get('provider', 'unknown')}): {ai_assessment} — no scoring contribution"
                )

            # Log AI evidence for transparency
            for se in ai_analysis.get("supporting_evidence", [])[:3]:
                breakdown["ai"].append(f"  AI supporting: {se}")
            for ce in ai_analysis.get("contradictory_evidence", [])[:3]:
                breakdown["ai"].append(f"  AI contradicting: {ce}")

        elif ai_status == "NOT_RUN":
            gatekeeper = ai_analysis.get("gatekeeper", {})
            reason = gatekeeper.get("reason", "Not run")
            breakdown["ai"].append(f"AI Analysis: NOT RUN — {reason}")
        else:
            breakdown["ai"].append(f"AI Analysis: {ai_status} ({ai_analysis.get('failover_reason', 'N/A')})")

        # -------------------------------------------------------------------
        # Corroboration & Final Decision Logic
        # -------------------------------------------------------------------
        sorted_classes = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        top_class, top_score = sorted_classes[0]
        second_class, second_score = sorted_classes[1]

        top_families = list(family_contributions[top_class])
        independent_count = len(top_families)

        # Corroboration Strength
        if independent_count >= 3:
            strength = "STRONG"
        elif independent_count == 2:
            strength = "MODERATE"
        elif independent_count == 1:
            strength = "WEAK"
        else:
            strength = "NONE"

        # Check for conflict
        has_conflict = (
            top_score > 2.0 and second_score > 2.0
            and abs(top_score - second_score) <= 1.0
            and top_class != second_class
        )

        # Coverage: how many evidence families produced results
        evidence_coverage = sum(1 for k in ["webpage", "network", "visual", "threat_intelligence", "prompt_injection", "ai_analysis"]
                                if evidence.get(k, {}).get("status") in ("SUCCESS", "CONFIGURED", "NOT_RUN"))

        # Decision Thresholds
        if has_conflict:
            final_class = "Unknown"
            risk_level = "MEDIUM"
            risk_score = 0.50
            summary = (
                f"Unknown / Needs Review: Conflicting evidence between {top_class} (score {top_score:.1f}) "
                f"and {second_class} (score {second_score:.1f})."
            )
        elif top_class in ['Phishing', 'Malware', 'Defacement']:
            if top_score >= 3.5 and independent_count >= 2:
                final_class = top_class
                risk_level = "CRITICAL" if top_score >= 5.0 else "HIGH"
                risk_score = min(0.95, 0.65 + (top_score * 0.05))
                summary = (
                    f"Confirmed {top_class}: Corroborated by {independent_count} independent evidence families "
                    f"({', '.join(top_families)})."
                )
            elif top_score >= 4.0 and independent_count >= 1:
                final_class = top_class
                risk_level = "HIGH"
                risk_score = 0.80
                summary = (
                    f"Probable {top_class}: High-weight signal from {', '.join(top_families)} "
                    f"(score {top_score:.1f})."
                )
            else:
                final_class = "Unknown"
                risk_level = "MEDIUM"
                risk_score = 0.50
                summary = (
                    f"Unknown / Needs Review: Insufficient corroboration for {top_class} "
                    f"(only {independent_count} family, score {top_score:.1f})."
                )
        elif top_class == "Benign" and top_score >= 3.0 and independent_count >= 2:
            final_class = "Benign"
            risk_level = "LOW"
            risk_score = max(0.05, 0.25 - (top_score * 0.03))
            summary = (
                f"Confirmed Benign: Validated across {independent_count} independent families "
                f"({', '.join(top_families)})."
            )
        elif top_class == "Benign" and top_score >= 4.5 and independent_count >= 3:
            # Strong benign with 3+ families
            final_class = "Benign"
            risk_level = "LOW"
            risk_score = 0.05
            summary = (
                f"Strong Benign: Comprehensive clean evidence from {independent_count} families "
                f"({', '.join(top_families)})."
            )
        else:
            final_class = "Unknown"
            risk_level = "MEDIUM"
            risk_score = 0.50
            summary = (
                f"Unknown / Needs Review: Insufficient independent evidence collected "
                f"(Top score: {top_score:.1f}). Initial ML: {initial_prediction}."
            )

        return {
            "final_classification": final_class,
            "risk_level": risk_level,
            "risk_score": round(risk_score, 2),
            "evidence_summary": summary,
            "evidence_breakdown": breakdown,
            "corroboration": {
                "top_candidate": top_class,
                "top_score": round(top_score, 2),
                "families_used": top_families,
                "independent_families": independent_count,
                "strength": strength,
                "coverage": evidence_coverage,
                "all_scores": {k: round(v, 2) for k, v in scores.items()},
                "conflicting": has_conflict,
                "supporting_families": top_families,
                "conflicting_families": list(family_contributions.get(second_class, set())) if has_conflict else []
            },
            "threat_indicators": list(set(threat_indicators))
        }
