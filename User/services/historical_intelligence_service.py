"""
Historical Intelligence Service — Phase 6
Provides reusable, structured historical intelligence queries over existing
MySQL relational models (pari_scan, pari_url, pari_domain, pari_ip,
pari_prediction, pari_scan_fallback, pari_ai_evidence, pari_threat_indicator,
pari_scan_indicator, pari_analyst_review).

Key Features:
  1. Reusable structured historical intelligence for Nikhil and PARI.
  2. Multi-level matching: Exact URL history, Domain history, and IP history.
  3. Strict current scan exclusion (exclude_scan_id) to prevent circular evidence.
  4. User database isolation (queries execute strictly against current user/guest DB).
  5. Bounded, safe summaries with classification breakdown, risk stats, and indicator tracking.
  6. Historical evidence is supporting evidence only — deterministic corroboration logic
     remains authoritative.
"""

import logging
from typing import Optional, Dict, Any, List
from urllib.parse import urlparse
from django.db.models import Avg, Max, Count, Q
from django.utils import timezone

from User.db_manager import get_current_db

logger = logging.getLogger(__name__)


class HistoricalIntelligenceService:
    """
    Reusable structured historical intelligence service querying existing MySQL records.
    """

    @classmethod
    def get_historical_intelligence(
        cls,
        url: str,
        domain: Optional[str] = None,
        ip: Optional[str] = None,
        exclude_scan_id: Optional[int] = None,
        db_alias: Optional[str] = None,
        respect_history_clear: bool = False
    ) -> Dict[str, Any]:
        """
        Query MySQL historical memory for previous occurrences of URL, Domain, or IP.

        Args:
            url: Target URL string.
            domain: Target domain/hostname (optional; extracted from url if None).
            ip: Target resolved IP address (optional).
            exclude_scan_id: The scan ID currently in progress (MUST be excluded).
            db_alias: Django database connection alias (defaults to active request db).
            respect_history_clear: If True, filters out scans created before the user's latest
                                  HistoryClearEvent. If False (default), reflects full ground-truth memory.

        Returns:
            Dict containing bounded, structured historical intelligence.
        """
        target_db = db_alias or get_current_db() or 'guest_db'

        # Import models locally to prevent circular imports
        from User.models import (
            Scan, URL, Domain, IP, Prediction, ScanFallbackResult,
            ScanAIEvidence, ScanFinalDecision, ThreatIndicator, ScanIndicator,
            AnalystReview, HistoryClearEvent
        )

        parsed = urlparse(url if url.startswith(('http://', 'https://')) else f"http://{url}")
        host = (domain or parsed.hostname or url).lower().strip()
        target_url = url.strip()

        # Initialize base response
        result = {
            "status": "SUCCESS",
            "target_url": target_url,
            "target_domain": host,
            "target_ip": ip,
            "exclude_scan_id": exclude_scan_id,
            "exact_url_history": {
                "seen": False,
                "scan_count": 0,
                "first_seen": None,
                "last_seen": None,
                "classifications": {},
                "final_decision_classifications": {},
                "rf_classifications": {},
                "fallback_classifications": {},
                "ai_assessments": {},
                "avg_risk_score": None,
                "max_risk_score": None,
            },
            "domain_history": {
                "seen": False,
                "domain_name": host,
                "domain_status": "UNKNOWN",
                "domain_risk_score": 0.0,
                "scan_count": 0,
                "first_seen": None,
                "last_seen": None,
                "previous_classifications": {},
                "final_decision_classifications": {},
                "rf_classifications": {},
                "fallback_classifications": {},
                "ai_assessments": {},
                "avg_risk_score": None,
                "max_risk_score": None,
                "has_mixed_outcomes": False,
                "malicious_count": 0,
                "benign_count": 0,
            },
            "ip_history": {
                "seen": False,
                "ip_address": ip,
                "status": None,
                "country": None,
                "risk_score": None,
                "scan_count": 0,
            },
            "previous_indicators": [],
            "repeated_indicators": [],
            "analyst_reviews": {
                "review_count": 0,
                "last_review_label": None,
                "validated_count": 0,
            },
            "last_seen": None,
            "first_seen": None,
            "historical_risk": None,
            "summary": "No previous history found",
            "match_found": False,
            "has_mixed_outcomes": False,
            # Backwards compatibility keys for existing Nikhil consumers
            "previous_scans_count": 0,
            "known_malicious_in_domain": 0,
            "historical_indicators": [],
            "domain_status": "UNKNOWN",
        }

        try:
            # Handle HistoryClearEvent if requested
            cleared_after = None
            if respect_history_clear:
                try:
                    latest_clear = HistoryClearEvent.objects.using(target_db).order_by('-cleared_at').first()
                    if latest_clear:
                        cleared_after = latest_clear.cleared_at
                except Exception as e:
                    logger.debug("Could not inspect HistoryClearEvent: %s", e)

            # -------------------------------------------------------------
            # 1. Domain History Lookup
            # -------------------------------------------------------------
            domain_obj = Domain.objects.using(target_db).filter(domain_name__iexact=host).first()
            domain_scans_qs = Scan.objects.none()

            if domain_obj:
                result["domain_history"]["domain_status"] = domain_obj.status
                result["domain_history"]["domain_risk_score"] = domain_obj.risk_score
                result["domain_status"] = domain_obj.status

                domain_scans_qs = Scan.objects.using(target_db).filter(url__domain=domain_obj)
                if exclude_scan_id is not None:
                    domain_scans_qs = domain_scans_qs.exclude(id=exclude_scan_id)
                if cleared_after is not None:
                    domain_scans_qs = domain_scans_qs.filter(created_at__gt=cleared_after)

                domain_count = domain_scans_qs.count()
                if domain_count > 0:
                    result["domain_history"]["seen"] = True
                    result["domain_history"]["scan_count"] = domain_count
                    result["previous_scans_count"] = domain_count

                    first_scan = domain_scans_qs.order_by('created_at').first()
                    last_scan = domain_scans_qs.order_by('-created_at').first()
                    if first_scan and first_scan.created_at:
                        result["domain_history"]["first_seen"] = first_scan.created_at.isoformat()
                        result["first_seen"] = first_scan.created_at.isoformat()
                    if last_scan and last_scan.created_at:
                        result["domain_history"]["last_seen"] = last_scan.created_at.isoformat()
                        result["last_seen"] = last_scan.created_at.isoformat()

                    # Extract classifications, risks, and AI assessments across domain scans
                    scans_with_rel = list(
                        domain_scans_qs.select_related(
                            'prediction', 'fallback_result', 'ai_evidence', 'final_decision'
                        ).order_by('-created_at')[:100]  # bounded inspect set
                    )

                    risk_scores = []
                    mal_count = 0
                    benign_count = 0
                    prev_classes = {}
                    rf_classes = {}
                    fb_classes = {}
                    ai_classes = {}
                    fd_classes = {}

                    for s in scans_with_rel:
                        # Priority for final outcome: ScanFinalDecision > ScanFallbackResult > Prediction (RF)
                        final_class = None
                        if hasattr(s, 'final_decision') and s.final_decision:
                            fdec_cls = s.final_decision.final_classification
                            fd_classes[fdec_cls] = fd_classes.get(fdec_cls, 0) + 1
                            final_class = fdec_cls
                            if s.final_decision.risk_score is not None:
                                risk_scores.append(s.final_decision.risk_score)

                        if hasattr(s, 'fallback_result') and s.fallback_result:
                            fb_cls = s.fallback_result.classification
                            fb_classes[fb_cls] = fb_classes.get(fb_cls, 0) + 1
                            if final_class is None:
                                final_class = fb_cls
                            if not hasattr(s, 'final_decision') or not s.final_decision:
                                if s.fallback_result.risk_score is not None:
                                    risk_scores.append(s.fallback_result.risk_score)

                        if hasattr(s, 'prediction') and s.prediction:
                            rf_cls = s.prediction.predicted_class
                            rf_classes[rf_cls] = rf_classes.get(rf_cls, 0) + 1
                            if final_class is None:
                                final_class = rf_cls
                            if (not hasattr(s, 'final_decision') or not s.final_decision) and (not hasattr(s, 'fallback_result') or not s.fallback_result):
                                if s.prediction.risk_score is not None:
                                    risk_scores.append(s.prediction.risk_score)

                        if hasattr(s, 'ai_evidence') and s.ai_evidence and s.ai_evidence.assessment:
                            ai_ass = s.ai_evidence.assessment
                            ai_classes[ai_ass] = ai_classes.get(ai_ass, 0) + 1

                        if final_class:
                            prev_classes[final_class] = prev_classes.get(final_class, 0) + 1
                            if final_class in ('Phishing', 'Malware', 'Defacement'):
                                mal_count += 1
                            elif final_class == 'Benign':
                                benign_count += 1

                    result["domain_history"]["previous_classifications"] = prev_classes
                    result["domain_history"]["final_decision_classifications"] = fd_classes
                    result["domain_history"]["rf_classifications"] = rf_classes
                    result["domain_history"]["fallback_classifications"] = fb_classes
                    result["domain_history"]["ai_assessments"] = ai_classes
                    result["domain_history"]["malicious_count"] = mal_count
                    result["domain_history"]["benign_count"] = benign_count
                    result["known_malicious_in_domain"] = mal_count

                    has_mixed = bool(benign_count > 0 and mal_count > 0)
                    result["domain_history"]["has_mixed_outcomes"] = has_mixed
                    result["has_mixed_outcomes"] = has_mixed

                    if risk_scores:
                        avg_risk = round(sum(risk_scores) / len(risk_scores), 4)
                        max_risk = round(max(risk_scores), 4)
                        result["domain_history"]["avg_risk_score"] = avg_risk
                        result["domain_history"]["max_risk_score"] = max_risk
                        result["historical_risk"] = max_risk

            # -------------------------------------------------------------
            # 2. Exact URL History Lookup
            # -------------------------------------------------------------
            url_obj = URL.objects.using(target_db).filter(url=target_url).first()
            if url_obj:
                url_scans_qs = Scan.objects.using(target_db).filter(url=url_obj)
                if exclude_scan_id is not None:
                    url_scans_qs = url_scans_qs.exclude(id=exclude_scan_id)
                if cleared_after is not None:
                    url_scans_qs = url_scans_qs.filter(created_at__gt=cleared_after)

                url_count = url_scans_qs.count()
                if url_count > 0:
                    result["exact_url_history"]["seen"] = True
                    result["exact_url_history"]["scan_count"] = url_count

                    first_u_scan = url_scans_qs.order_by('created_at').first()
                    last_u_scan = url_scans_qs.order_by('-created_at').first()
                    if first_u_scan and first_u_scan.created_at:
                        result["exact_url_history"]["first_seen"] = first_u_scan.created_at.isoformat()
                    if last_u_scan and last_u_scan.created_at:
                        result["exact_url_history"]["last_seen"] = last_u_scan.created_at.isoformat()

                    u_scans_with_rel = list(
                        url_scans_qs.select_related(
                            'prediction', 'fallback_result', 'ai_evidence', 'final_decision'
                        ).order_by('-created_at')[:50]
                    )

                    u_risk_scores = []
                    u_prev_classes = {}
                    u_rf_classes = {}
                    u_fb_classes = {}
                    u_ai_classes = {}
                    u_fd_classes = {}

                    for s in u_scans_with_rel:
                        final_cls = None
                        if hasattr(s, 'final_decision') and s.final_decision:
                            u_fdec_cls = s.final_decision.final_classification
                            u_fd_classes[u_fdec_cls] = u_fd_classes.get(u_fdec_cls, 0) + 1
                            final_cls = u_fdec_cls
                            if s.final_decision.risk_score is not None:
                                u_risk_scores.append(s.final_decision.risk_score)

                        if hasattr(s, 'fallback_result') and s.fallback_result:
                            fb_cls = s.fallback_result.classification
                            u_fb_classes[fb_cls] = u_fb_classes.get(fb_cls, 0) + 1
                            if final_cls is None:
                                final_cls = fb_cls
                            if not hasattr(s, 'final_decision') or not s.final_decision:
                                if s.fallback_result.risk_score is not None:
                                    u_risk_scores.append(s.fallback_result.risk_score)

                        if hasattr(s, 'prediction') and s.prediction:
                            rf_cls = s.prediction.predicted_class
                            u_rf_classes[rf_cls] = u_rf_classes.get(rf_cls, 0) + 1
                            if final_cls is None:
                                final_cls = rf_cls
                            if (not hasattr(s, 'final_decision') or not s.final_decision) and (not hasattr(s, 'fallback_result') or not s.fallback_result):
                                if s.prediction.risk_score is not None:
                                    u_risk_scores.append(s.prediction.risk_score)

                        if hasattr(s, 'ai_evidence') and s.ai_evidence and s.ai_evidence.assessment:
                            ai_ass = s.ai_evidence.assessment
                            u_ai_classes[ai_ass] = u_ai_classes.get(ai_ass, 0) + 1

                        if final_cls:
                            u_prev_classes[final_cls] = u_prev_classes.get(final_cls, 0) + 1

                    result["exact_url_history"]["classifications"] = u_prev_classes
                    result["exact_url_history"]["final_decision_classifications"] = u_fd_classes
                    result["exact_url_history"]["rf_classifications"] = u_rf_classes
                    result["exact_url_history"]["fallback_classifications"] = u_fb_classes
                    result["exact_url_history"]["ai_assessments"] = u_ai_classes

                    if u_risk_scores:
                        result["exact_url_history"]["avg_risk_score"] = round(sum(u_risk_scores) / len(u_risk_scores), 4)
                        result["exact_url_history"]["max_risk_score"] = round(max(u_risk_scores), 4)

            # -------------------------------------------------------------
            # 3. IP History Lookup (if IP provided)
            # -------------------------------------------------------------
            if ip:
                ip_obj = IP.objects.using(target_db).filter(ip_address=ip).first()
                ip_scan_count = 0
                if ip_obj:
                    result["ip_history"]["status"] = ip_obj.status
                    result["ip_history"]["country"] = ip_obj.country
                    result["ip_history"]["risk_score"] = ip_obj.risk_score

                # Find scans associated with this IP through ThreatIndicator
                ip_scans_qs = ScanIndicator.objects.using(target_db).filter(
                    indicator__indicator_type='IP_ADDRESS',
                    indicator__indicator_value=ip
                )
                if exclude_scan_id is not None:
                    ip_scans_qs = ip_scans_qs.exclude(scan_id=exclude_scan_id)

                ip_scan_count = ip_scans_qs.values('scan_id').distinct().count()
                result["ip_history"]["scan_count"] = ip_scan_count
                result["ip_history"]["seen"] = bool(ip_scan_count > 0 or (ip_obj and ip_obj.status != 'UNKNOWN'))

            # -------------------------------------------------------------
            # 4. Threat Indicators History (Bounded)
            # -------------------------------------------------------------
            if domain_scans_qs.exists():
                indicator_qs = (
                    ThreatIndicator.objects.using(target_db)
                    .filter(scanindicator__scan__in=domain_scans_qs)
                    .annotate(frequency=Count('scanindicator'))
                    .order_by('-frequency', '-created_at')[:15]
                )

                for ind in indicator_qs:
                    item = {
                        "type": ind.indicator_type,
                        "value": ind.indicator_value,
                        "severity": ind.severity,
                        "frequency": ind.frequency,
                    }
                    result["previous_indicators"].append(item)
                    # Legacy structure for threat_intel.py
                    result["historical_indicators"].append({
                        "type": ind.indicator_type,
                        "value": ind.indicator_value,
                        "severity": ind.severity,
                    })
                    if ind.frequency > 1:
                        result["repeated_indicators"].append(item)

            # -------------------------------------------------------------
            # 5. Analyst Review History
            # -------------------------------------------------------------
            if domain_scans_qs.exists():
                reviews_qs = AnalystReview.objects.using(target_db).filter(scan__in=domain_scans_qs)
                rev_count = reviews_qs.count()
                if rev_count > 0:
                    result["analyst_reviews"]["review_count"] = rev_count
                    latest_rev = reviews_qs.order_by('-reviewed_at').first()
                    if latest_rev:
                        result["analyst_reviews"]["last_review_label"] = latest_rev.final_label
                    val_count = reviews_qs.filter(validation_status='VALIDATED').count()
                    result["analyst_reviews"]["validated_count"] = val_count

            # -------------------------------------------------------------
            # 6. Synthesize Match Status and Bounded Summary
            # -------------------------------------------------------------
            has_domain_hist = result["domain_history"]["seen"]
            has_url_hist = result["exact_url_history"]["seen"]
            has_ip_hist = result["ip_history"]["seen"]
            result["match_found"] = bool(has_domain_hist or has_url_hist or has_ip_hist)

            if not result["match_found"]:
                result["summary"] = "No previous history found"
            else:
                summary_parts = []
                d_count = result["domain_history"]["scan_count"]
                u_count = result["exact_url_history"]["scan_count"]
                mal = result["domain_history"]["malicious_count"]
                benign = result["domain_history"]["benign_count"]
                has_mixed = result["domain_history"]["has_mixed_outcomes"]

                if has_url_hist:
                    summary_parts.append(f"Exact URL scanned {u_count} time{'s' if u_count > 1 else ''} previously")

                if has_domain_hist:
                    classes_str = ", ".join(f"{k}: {v}" for k, v in result["domain_history"]["previous_classifications"].items())
                    if has_mixed:
                        summary_parts.append(f"Domain '{host}' has mixed history ({classes_str}) across {d_count} prior scan{'s' if d_count > 1 else ''}")
                    elif mal > 0:
                        summary_parts.append(f"Domain '{host}' has {mal} prior malicious scan{'s' if mal > 1 else ''} out of {d_count}")
                    elif benign > 0:
                        summary_parts.append(f"Domain '{host}' previously seen {d_count} time{'s' if d_count > 1 else ''} as Benign")
                    else:
                        summary_parts.append(f"Domain '{host}' seen {d_count} time{'s' if d_count > 1 else ''}")

                rep_count = len(result["repeated_indicators"])
                if rep_count > 0:
                    summary_parts.append(f"{rep_count} repeated threat indicator{'s' if rep_count > 1 else ''} on record")

                result["summary"] = "; ".join(summary_parts)[:500]

        except Exception as e:
            logger.warning(f"Error executing HistoricalIntelligenceService lookup for {url}: {e}")
            result["status"] = "ERROR"
            result["error"] = str(e)
            result["summary"] = f"Historical lookup error: {e}"[:500]

        return result

    @classmethod
    def get_domain_profile(
        cls,
        domain_name: str,
        exclude_scan_id: Optional[int] = None,
        db_alias: Optional[str] = None,
        respect_history_clear: bool = False,
    ) -> Dict[str, Any]:
        """
        Derive dynamic domain-level historical intelligence profile from existing relational records.

        Args:
            domain_name: Target domain name (e.g. 'example.com').
            exclude_scan_id: Optional current scan ID to exclude from calculations.
            db_alias: Optional database connection alias for user isolation.
            respect_history_clear: If True, filters out scans created before the user's latest
                                  HistoryClearEvent. If False (default), reflects full ground-truth memory.

        Returns:
            Dict containing bounded, comprehensive domain profile.
        """
        target_db = db_alias or get_current_db() or 'guest_db'

        from User.models import (
            Scan, Domain, ThreatIndicator, ScanIndicator, AnalystReview, HistoryClearEvent,
            ScanFinalDecision
        )

        host = domain_name.lower().strip()

        # Handle HistoryClearEvent if requested
        cleared_after = None
        if respect_history_clear:
            try:
                latest_clear = HistoryClearEvent.objects.using(target_db).order_by('-cleared_at').first()
                if latest_clear:
                    cleared_after = latest_clear.cleared_at
            except Exception as e:
                logger.debug("Could not inspect HistoryClearEvent: %s", e)

        profile = {
            "domain": host,
            "seen": False,
            "status": "UNKNOWN",
            "domain_risk_score": 0.0,
            "first_seen": None,
            "last_seen": None,
            "scan_count": 0,
            "distinct_url_count": 0,
            "most_frequent_url": None,
            "classification_counts": {},
            "final_decision_counts": {},
            "rf_classification_counts": {},
            "fallback_classification_counts": {},
            "mixed_history": False,
            "indicator_count": 0,
            "repeated_indicator_count": 0,
            "top_indicators": [],
            "ai_assessment_counts": {},
            "historical_fallback_risk": {
                "avg": None,
                "max": None,
                "min": None,
                "count": 0,
            },
            "analyst_reviews": {
                "count": 0,
                "last_label": None,
                "validated_count": 0,
            },
            "history_cleared_filtered": bool(cleared_after is not None),
        }

        try:
            domain_obj = Domain.objects.using(target_db).filter(domain_name__iexact=host).first()
            if not domain_obj:
                return profile

            profile["status"] = domain_obj.status
            profile["domain_risk_score"] = domain_obj.risk_score

            scans_qs = Scan.objects.using(target_db).filter(url__domain=domain_obj)
            if exclude_scan_id is not None:
                scans_qs = scans_qs.exclude(id=exclude_scan_id)
            if cleared_after is not None:
                scans_qs = scans_qs.filter(created_at__gt=cleared_after)

            total_scans = scans_qs.count()
            if total_scans == 0:
                return profile

            profile["seen"] = True
            profile["scan_count"] = total_scans

            first_scan = scans_qs.order_by('created_at').first()
            last_scan = scans_qs.order_by('-created_at').first()
            if first_scan and first_scan.created_at:
                profile["first_seen"] = first_scan.created_at.isoformat()
            if last_scan and last_scan.created_at:
                profile["last_seen"] = last_scan.created_at.isoformat()

            # Distinct URL count and most frequent URL
            url_aggregates = (
                scans_qs.values('url__url')
                .annotate(freq=Count('id'))
                .order_by('-freq')
            )
            profile["distinct_url_count"] = url_aggregates.count()
            if url_aggregates.exists():
                profile["most_frequent_url"] = url_aggregates.first()['url__url']

            # Classification counts adhering to Phase 3/10 semantics (NO double counting)
            # Scan-by-scan classification: final decision if exists, else fallback classification if exists, else initial RF
            scans_list = list(
                scans_qs.select_related('prediction', 'fallback_result', 'ai_evidence', 'final_decision')[:200]
            )

            class_counts = {}
            fd_counts = {}
            rf_counts = {}
            fb_counts = {}
            ai_counts = {}
            fallback_risks = []

            for s in scans_list:
                rf_cls = None
                if hasattr(s, 'prediction') and s.prediction:
                    rf_cls = s.prediction.predicted_class
                    rf_counts[rf_cls] = rf_counts.get(rf_cls, 0) + 1

                final_outcome = None
                if hasattr(s, 'final_decision') and s.final_decision:
                    fdec_cls = s.final_decision.final_classification
                    fd_counts[fdec_cls] = fd_counts.get(fdec_cls, 0) + 1
                    final_outcome = fdec_cls

                if hasattr(s, 'fallback_result') and s.fallback_result:
                    fb_cls = s.fallback_result.classification
                    fb_counts[fb_cls] = fb_counts.get(fb_cls, 0) + 1
                    if final_outcome is None:
                        final_outcome = fb_cls
                    if s.fallback_result.risk_score is not None:
                        fallback_risks.append(s.fallback_result.risk_score)
                elif final_outcome is None:
                    final_outcome = rf_cls or 'Unknown'

                class_counts[final_outcome] = class_counts.get(final_outcome, 0) + 1

                if hasattr(s, 'ai_evidence') and s.ai_evidence and s.ai_evidence.assessment:
                    ai_ass = s.ai_evidence.assessment
                    ai_counts[ai_ass] = ai_counts.get(ai_ass, 0) + 1

            profile["classification_counts"] = class_counts
            profile["final_decision_counts"] = fd_counts
            profile["rf_classification_counts"] = rf_counts
            profile["fallback_classification_counts"] = fb_counts
            profile["ai_assessment_counts"] = ai_counts

            has_benign = class_counts.get("Benign", 0) > 0
            has_malicious = any(class_counts.get(m, 0) > 0 for m in ("Phishing", "Malware", "Defacement"))
            profile["mixed_history"] = bool(has_benign and has_malicious)

            # Historical Fallback Risk (purely fallback risk; never mixed with RF/AI confidences)
            if fallback_risks:
                profile["historical_fallback_risk"] = {
                    "avg": round(sum(fallback_risks) / len(fallback_risks), 4),
                    "max": round(max(fallback_risks), 4),
                    "min": round(min(fallback_risks), 4),
                    "count": len(fallback_risks),
                }

            # Threat Indicators History
            indicator_qs = (
                ThreatIndicator.objects.using(target_db)
                .filter(scanindicator__scan__in=scans_qs)
                .annotate(frequency=Count('scanindicator'))
                .order_by('-frequency', '-created_at')[:20]
            )
            profile["indicator_count"] = indicator_qs.count()
            rep_count = 0
            top_inds = []
            for ind in indicator_qs:
                if ind.frequency > 1:
                    rep_count += 1
                top_inds.append({
                    "type": ind.indicator_type,
                    "value": ind.indicator_value,
                    "severity": ind.severity,
                    "frequency": ind.frequency,
                })
            profile["repeated_indicator_count"] = rep_count
            profile["top_indicators"] = top_inds

            # Analyst Reviews
            rev_qs = AnalystReview.objects.using(target_db).filter(scan__in=scans_qs)
            rev_count = rev_qs.count()
            if rev_count > 0:
                latest_rev = rev_qs.order_by('-reviewed_at').first()
                profile["analyst_reviews"] = {
                    "count": rev_count,
                    "last_label": latest_rev.final_label if latest_rev else None,
                    "validated_count": rev_qs.filter(validation_status='VALIDATED').count(),
                }

        except Exception as e:
            logger.warning(f"Error computing domain profile for {domain_name}: {e}")
            profile["error"] = str(e)

        return profile


class DomainIntelligenceService:
    """
    Dedicated interface for Domain-Level Historical Intelligence queries.
    """

    @classmethod
    def get_domain_profile(
        cls,
        domain_name: str,
        exclude_scan_id: Optional[int] = None,
        db_alias: Optional[str] = None,
        respect_history_clear: bool = False,
    ) -> Dict[str, Any]:
        """
        Delegate to HistoricalIntelligenceService.get_domain_profile.
        """
        return HistoricalIntelligenceService.get_domain_profile(
            domain_name=domain_name,
            exclude_scan_id=exclude_scan_id,
            db_alias=db_alias,
            respect_history_clear=respect_history_clear,
        )
