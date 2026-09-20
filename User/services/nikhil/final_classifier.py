import logging

logger = logging.getLogger(__name__)

class FinalClassifier:
    """
    Evidence Corroboration and Final Classification Engine.
    
    IMPORTANT RULES:
    1. Does NOT simply return the initial Random Forest class.
    2. Preserves initial_prediction and initial_confidence.
    3. Combines evidence from multiple independent evidence families:
       - Webpage / HTML / DOM
       - Text / Content
       - Visual / Screenshot
       - Network / DNS / SSL
       - Threat Intelligence / SQL Correlation
       - Prompt Injection
    4. Evaluates engineering evidence scores for: Benign, Phishing, Malware, Defacement.
    5. Requires corroboration across MULTIPLE independent families for high confidence.
    6. If evidence is insufficient or conflicting -> returns 'Unknown' (Needs Review).
    """

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
                "final_classification": str ('Benign'|'Phishing'|'Malware'|'Defacement'|'Unknown'),
                "risk_level": str ('LOW'|'MEDIUM'|'HIGH'|'CRITICAL'),
                "risk_score": float (0.0 to 1.0),
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
        
        # Breakdown trackers
        breakdown = {
            "webpage": [],
            "visual": [],
            "network": [],
            "threat_intelligence": [],
            "prompt_injection": [],
            "ai": []
        }
        
        threat_indicators = []
        
        # Family score boards: map class -> list of contributing family names
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

        # -------------------------------------------------------------
        # Family 1: Webpage / HTML Evidence
        # -------------------------------------------------------------
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
                breakdown["webpage"].append("Credential harvesting phrase detected in page text (+2.0 Phishing)")
                threat_indicators.append("TEXT:CREDENTIAL_HARVESTING")

            if "DEFACEMENT_TEXT" in wp_indicators:
                scores["Defacement"] += 3.5
                family_contributions["Defacement"].add("TEXT")
                breakdown["webpage"].append("Defacement keyword pattern detected in visible text (+3.5 Defacement)")
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
                breakdown["webpage"].append("Hidden text elements found on page (+0.5 Phishing/Defacement)")

            # Check if page structure is completely benign (clean forms, clean text, valid structure)
            if not wp_indicators and webpage.get("page_structure", {}).get("num_tags", 0) > 10:
                scores["Benign"] += 2.0
                family_contributions["Benign"].add("WEBPAGE")
                breakdown["webpage"].append("Standard benign HTML structure without suspicious indicators (+2.0 Benign)")
        else:
            breakdown["webpage"].append(f"Webpage fetch status: {wp_status}")

        # -------------------------------------------------------------
        # Family 2: Network / DNS / SSL Evidence
        # -------------------------------------------------------------
        net_status = network.get("status")
        if net_status == "SUCCESS":
            if network.get("is_ip_address"):
                scores["Phishing"] += 1.5
                scores["Malware"] += 1.5
                family_contributions["Phishing"].add("NETWORK")
                family_contributions["Malware"].add("NETWORK")
                breakdown["network"].append("Host is a raw IP address instead of registered domain (+1.5 Phishing/Malware)")
                threat_indicators.append("NETWORK:RAW_IP_HOST")

            ssl_info = network.get("ssl", {})
            if ssl_info.get("verified") is True:
                scores["Benign"] += 1.5
                family_contributions["Benign"].add("NETWORK")
                breakdown["network"].append("Valid SSL certificate with trusted CA verified (+1.5 Benign)")
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
                breakdown["network"].append("Multiple redirect hops detected in chain (+1.0 Phishing/Malware)")
                threat_indicators.append("NETWORK:EXCESSIVE_REDIRECTS")
        else:
            breakdown["network"].append(f"Network status: {net_status}")

        # -------------------------------------------------------------
        # Family 3: Visual / Screenshot Evidence
        # -------------------------------------------------------------
        vis_status = visual.get("status")
        if vis_status == "SUCCESS":
            breakdown["visual"].append(f"Screenshot reference captured: {visual.get('screenshot_reference')}")
            for finding in visual.get("visual_findings", []):
                breakdown["visual"].append(f"Visual observation: {finding}")
        else:
            breakdown["visual"].append(f"Visual module: {vis_status} ({visual.get('error') or 'Unavailable'})")

        # -------------------------------------------------------------
        # Family 4: Threat Intelligence / Local SQL Correlation
        # -------------------------------------------------------------
        ti_status = threat_intel.get("status")
        local_correl = threat_intel.get("local_correlation", {})
        known_malicious = local_correl.get("known_malicious_in_domain", 0)
        
        if known_malicious > 0:
            scores["Phishing"] += 2.0
            scores["Malware"] += 2.0
            family_contributions["Phishing"].add("SQL_CORRELATION")
            family_contributions["Malware"].add("SQL_CORRELATION")
            breakdown["threat_intelligence"].append(
                f"SQL Correlation: Domain linked to {known_malicious} previously detected malicious scans (+2.0)"
            )
            threat_indicators.append("CORRELATION:HISTORICAL_MALICIOUS_DOMAIN")
            
        for ind in threat_intel.get("external_indicators", []):
            threat_indicators.append(f"THREAT_INTEL:{ind}")

        if ti_status == "UNAVAILABLE":
            breakdown["threat_intelligence"].append("External threat intelligence provider UNAVAILABLE (No API key)")

        # -------------------------------------------------------------
        # Family 5: Prompt-Injection Detection
        # -------------------------------------------------------------
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

        # -------------------------------------------------------------
        # Family 6: AI Analysis Module (Locked MOCK/UNAVAILABLE)
        # -------------------------------------------------------------
        breakdown["ai"].append("AI Module: MOCK / UNAVAILABLE (Excluded from this task)")

        # -------------------------------------------------------------
        # Corroboration & Final Decision Logic
        # -------------------------------------------------------------
        # Determine highest scoring class
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

        # Check for conflict: if two distinct malicious/benign categories have close scores
        has_conflict = (top_score > 2.0 and second_score > 2.0 and abs(top_score - second_score) <= 1.0 and top_class != second_class)

        # Decision Thresholds:
        # Require >= 2 independent families OR very high score (>= 4.0) with at least 1 family
        # If insufficient evidence: return 'Unknown' (Needs Review) - DO NOT COPY ML CLASS
        if has_conflict:
            final_class = "Unknown"
            risk_level = "MEDIUM"
            risk_score = 0.50
            summary = f"Unknown / Needs Review: Conflicting evidence between {top_class} (score {top_score:.1f}) and {second_class} (score {second_score:.1f})."
        elif top_class in ['Phishing', 'Malware', 'Defacement']:
            if top_score >= 3.5 and independent_count >= 2:
                final_class = top_class
                risk_level = "CRITICAL" if top_score >= 5.0 else "HIGH"
                risk_score = min(0.95, 0.65 + (top_score * 0.05))
                summary = f"Confirmed {top_class}: Corroborated by {independent_count} independent evidence families ({', '.join(top_families)})."
            elif top_score >= 4.0 and independent_count >= 1:
                final_class = top_class
                risk_level = "HIGH"
                risk_score = 0.80
                summary = f"Probable {top_class}: High-weight signal from {', '.join(top_families)} (score {top_score:.1f})."
            else:
                # Weak or single uncorroborated evidence -> Unknown
                final_class = "Unknown"
                risk_level = "MEDIUM"
                risk_score = 0.50
                summary = f"Unknown / Needs Review: Insufficient corroboration for initial indication of {top_class} (only {independent_count} family, score {top_score:.1f})."
        elif top_class == "Benign" and top_score >= 3.0 and independent_count >= 2:
            final_class = "Benign"
            risk_level = "LOW"
            risk_score = max(0.05, 0.25 - (top_score * 0.03))
            summary = f"Confirmed Benign: Validated clean structure and verified SSL across {independent_count} independent families."
        else:
            # Insufficient evidence overall
            final_class = "Unknown"
            risk_level = "MEDIUM"
            risk_score = 0.50
            summary = f"Unknown / Needs Review: Insufficient independent evidence collected to corroborate classification (Top score: {top_score:.1f}). Initial ML: {initial_prediction}."

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
                "all_scores": {k: round(v, 2) for k, v in scores.items()}
            },
            "threat_indicators": list(set(threat_indicators))
        }
