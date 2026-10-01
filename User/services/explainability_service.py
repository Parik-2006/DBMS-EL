"""
Evidence Explainability and Provenance Service (Phase 9 & Phase 10).

Answers:
"What evidence was observed for Scan X,
which subsystem produced it,
and what safe reason was recorded?"

Preserves strict user isolation by querying the active user's isolated database.
"""
import logging
from django.db import models
from django.utils import timezone
from User.db_manager import get_current_db

logger = logging.getLogger(__name__)


class EvidenceExplainabilityService:
    """
    Structured query service that explains a scan's evidence provenance
    and final decision record directly from MySQL.
    """

    @classmethod
    def _get_target_db(cls, target_db=None):
        return target_db or get_current_db() or 'guest_db'

    @classmethod
    def explain_scan(cls, scan_id, target_db=None):
        """
        Produce a structured evidence provenance explanation for a scan.

        Returns both a structured dictionary and a human-readable formatted string
        matching the Phase 9 specification.
        """
        from User.models import (
            Scan, Prediction, ScanFeatures, ScanFallbackResult,
            ScanEvidenceSummary, ScanAIEvidence, ScanIndicator,
            ScanFinalDecision
        )

        db = cls._get_target_db(target_db)

        try:
            scan = Scan.objects.using(db).select_related('url', 'url__domain').get(id=scan_id)
        except Scan.DoesNotExist:
            return {
                "scan_id": scan_id,
                "error": f"Scan {scan_id} not found in database {db}",
                "formatted_explanation": f"SCAN {scan_id}\nNot found."
            }

        # 1. Initial ML Prediction
        pred = Prediction.objects.using(db).filter(scan=scan).first()
        initial_ml = None
        if pred:
            initial_ml = {
                "model_name": pred.model_name,
                "predicted_class": pred.predicted_class,
                "confidence": pred.confidence,
                "risk_score": pred.risk_score,
                "threshold_used": pred.threshold_used,
                "is_confident": pred.is_confident,
                "probabilities": pred.probabilities,
            }

        # 2. Features
        feat = ScanFeatures.objects.using(db).filter(scan=scan).first()
        pari_features = None
        if feat:
            pari_features = {
                "url_len": feat.url_len,
                "letters_count": feat.letters_count,
                "digits_count": feat.digits_count,
                "special_chars_count": feat.special_chars_count,
                "shortened": feat.shortened,
                "abnormal_url": feat.abnormal_url,
                "secure_http": feat.secure_http,
                "have_ip": feat.have_ip,
                "url_region": feat.url_region,
                "root_domain": feat.root_domain,
            }

        # 3. Fallback Result
        fallback_obj = ScanFallbackResult.objects.using(db).filter(scan=scan).first()
        fallback_data = None
        if fallback_obj:
            fallback_data = {
                "service_name": fallback_obj.service_name,
                "classification": fallback_obj.classification,
                "risk_score": fallback_obj.risk_score,
                "risk_level": fallback_obj.risk_level,
                "evidence_summary": fallback_obj.evidence_summary,
                "mongo_document_reference": fallback_obj.mongo_document_reference,
            }

        # 4. Final Decision
        final_dec = ScanFinalDecision.objects.using(db).filter(scan=scan).first()
        final_decision_data = None
        if final_dec:
            final_decision_data = {
                "final_classification": final_dec.final_classification,
                "risk_score": final_dec.risk_score,
                "risk_level": final_dec.risk_level,
                "decision_status": final_dec.decision_status,
                "decision_method": final_dec.decision_method,
                "corroboration_strength": final_dec.corroboration_strength,
                "evidence_family_count": final_dec.evidence_family_count,
                "conflict_detected": final_dec.conflict_detected,
                "decision_summary": final_dec.decision_summary,
                "decision_timestamp": final_dec.decision_timestamp.isoformat() if final_dec.decision_timestamp else None,
            }

        # 5. Evidence Summaries
        summaries = list(ScanEvidenceSummary.objects.using(db).filter(scan=scan).order_by('id'))
        evidence_summaries_data = [
            {
                "family": s.evidence_family,
                "source_component": s.source_component or cls._default_family_source(s.evidence_family),
                "status": s.status,
                "detected": s.detected,
                "match_found": s.match_found,
                "source_count": s.source_count,
                "evidence_count": s.evidence_count,
                "severity": s.severity,
                "summary": s.summary,
            }
            for s in summaries
        ]

        # 6. Scan Indicators
        indicators = list(
            ScanIndicator.objects.using(db)
            .filter(scan=scan)
            .select_related('indicator')
            .order_by('id')
        )
        indicators_data = [
            {
                "type": ind.indicator.indicator_type,
                "value": ind.indicator.indicator_value,
                "source_component": ind.source_component or cls._infer_indicator_source(ind.indicator.indicator_type),
                "severity": ind.severity or ind.indicator.severity,
                "reason": ind.reason or f"Indicator recorded: {ind.indicator.indicator_value}",
                "detected_at": ind.detected_at.isoformat() if ind.detected_at else None,
            }
            for ind in indicators
        ]

        # 7. AI Evidence
        ai_obj = ScanAIEvidence.objects.using(db).filter(scan=scan).first()
        ai_data = None
        if ai_obj:
            ai_data = {
                "provider": ai_obj.provider or "Gemini",
                "model": ai_obj.model,
                "status": ai_obj.status,
                "assessment": ai_obj.assessment,
                "confidence": ai_obj.confidence,
                "risk_score": ai_obj.risk_score,
                "ai_required": ai_obj.ai_required,
                "ai_called": ai_obj.ai_called,
                "reasoning_summary": ai_obj.reasoning_summary,
            }

        # Build clean structured evidence items list
        evidence_items = []

        # Indicators as granular evidence items
        for ind in indicators_data:
            evidence_items.append({
                "family": ind["type"],
                "source": ind["source_component"],
                "type": ind["value"],
                "severity": ind["severity"],
                "reason": ind["reason"],
            })

        # Family summaries as broader evidence items
        for sm in evidence_summaries_data:
            evidence_items.append({
                "family": sm["family"],
                "source": sm["source_component"],
                "status": sm["status"],
                "detected": sm["detected"],
                "match_found": sm["match_found"],
                "severity": sm["severity"] or "INFO",
                "reason": sm["summary"],
            })

        # AI evidence item if present
        if ai_data and ai_data["status"] != "NOT_RUN":
            evidence_items.append({
                "family": "AI",
                "source": ai_data["provider"] or "Gemini",
                "assessment": ai_data["assessment"],
                "confidence": ai_data["confidence"],
                "severity": "HIGH" if (ai_data["risk_score"] or 0) >= 0.7 else "MEDIUM",
                "reason": ai_data["reasoning_summary"] or f"AI assessment: {ai_data['assessment']}",
            })

        # Format human-readable text
        formatted_text = cls._format_explanation_text(
            scan_id=scan.id,
            url=scan.url.url,
            initial_ml=initial_ml,
            final_decision=final_decision_data,
            indicators=indicators_data,
            summaries=evidence_summaries_data,
            ai_data=ai_data
        )

        return {
            "scan_id": scan.id,
            "url": scan.url.url,
            "domain": scan.url.domain.domain_name if scan.url.domain else None,
            "status": scan.status,
            "initial_ml": initial_ml,
            "pari_features": pari_features,
            "fallback": fallback_data,
            "final_decision": final_decision_data,
            "ai_evidence": ai_data,
            "indicators": indicators_data,
            "evidence_summaries": evidence_summaries_data,
            "evidence_items": evidence_items,
            "formatted_explanation": formatted_text,
        }

    @staticmethod
    def _default_family_source(family):
        mapping = {
            'WEBPAGE': 'WebpageAnalyzer',
            'NETWORK': 'NetworkAnalyzer',
            'VISUAL': 'VisualAnalyzer',
            'THREAT_INTELLIGENCE': 'ThreatIntelService',
            'PROMPT_INJECTION': 'PromptInjectionDetector',
            'SQL_HISTORY': 'HistoricalIntelligenceService',
            'TRUSTED_DOMAIN': 'TrustedDomainService',
            'AI': 'Gemini',
        }
        return mapping.get(family, 'NikhilCollector')

    @staticmethod
    def _infer_indicator_source(indicator_type):
        t = indicator_type.upper()
        if 'URL' in t or 'PARI' in t:
            return 'PARI'
        elif 'WEBPAGE' in t or 'TEXT' in t:
            return 'WebpageAnalyzer'
        elif 'NETWORK' in t or 'IP' in t or 'SSL' in t or 'DNS' in t:
            return 'NetworkAnalyzer'
        elif 'VISUAL' in t:
            return 'VisualAnalyzer'
        elif 'PROMPT' in t:
            return 'PromptInjectionDetector'
        elif 'THREAT' in t or 'URLHAUS' in t or 'ABUSE' in t:
            return 'ThreatIntelService'
        elif 'SQL' in t or 'REPUTATION' in t:
            return 'HistoricalIntelligenceService'
        elif 'TRUSTED' in t:
            return 'TrustedDomainService'
        return 'NikhilCollector'

    @classmethod
    def _format_explanation_text(cls, scan_id, url, initial_ml, final_decision,
                                indicators, summaries, ai_data):
        """
        Format scan explanation to match exact prompt specification.
        """
        lines = [
            f"SCAN {scan_id}",
            f"URL: {url}",
            "Evidence:",
            "----------------------------------------"
        ]

        # Group indicators by source/type
        for ind in indicators:
            lines.append(f"{ind['type']}")
            lines.append(f"  source = {ind['source_component']}")
            lines.append(f"  type = {ind['value']}")
            lines.append(f"  severity = {ind['severity']}")
            lines.append(f"  reason = {ind['reason']}")
            lines.append("")

        # Include summary families not covered by individual indicators
        ind_types = {ind['type'].upper() for ind in indicators}
        for sm in summaries:
            fam = sm['family']
            if fam not in ind_types:
                lines.append(f"{fam}")
                lines.append(f"  source = {sm['source_component']}")
                if sm['match_found'] is not None:
                    lines.append(f"  match = {str(sm['match_found']).lower()}")
                if sm['detected'] is not None:
                    lines.append(f"  detected = {str(sm['detected']).lower()}")
                if sm['severity']:
                    lines.append(f"  severity = {sm['severity']}")
                lines.append(f"  reason = {sm['summary']}")
                lines.append("")

        # AI section
        if ai_data and ai_data.get('status') != 'NOT_RUN':
            lines.append("AI")
            lines.append(f"  source = {ai_data.get('provider') or 'Gemini'}")
            lines.append(f"  assessment = {ai_data.get('assessment') or 'INCONCLUSIVE'}")
            if ai_data.get('confidence') is not None:
                lines.append(f"  confidence = {ai_data['confidence']:.2f}")
            if ai_data.get('reasoning_summary'):
                lines.append(f"  reason = {ai_data['reasoning_summary']}")
            lines.append("")

        # Final Decision footer
        if final_decision:
            lines.append("FINAL DECISION:")
            lines.append(f"  classification = {final_decision['final_classification']}")
            lines.append(f"  risk_score = {final_decision['risk_score']:.2f} ({final_decision['risk_level']})")
            lines.append(f"  method = {final_decision['decision_method']}")
            lines.append(f"  corroboration = {final_decision['corroboration_strength']} ({final_decision['evidence_family_count']} families)")
            if final_decision['conflict_detected']:
                lines.append("  conflict_detected = true")
            lines.append(f"  summary = {final_decision['decision_summary']}")

        return "\n".join(lines).strip()
