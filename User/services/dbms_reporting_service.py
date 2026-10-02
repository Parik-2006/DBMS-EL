"""
DBMS Intelligence Reporting Layer — Phase 12
Provides high-performance, read-only SQL queries and structured reports over
the normalized MySQL relational schema (pari_scan, pari_url, pari_domain,
pari_prediction, pari_scan_fallback, pari_evidence_summary, pari_ai_evidence,
pari_threat_indicator, pari_scan_indicator, pari_scan_features,
pari_final_decision).

Key Invariants:
  1. Read-Only: Never modifies any table, classification, or scan state.
  2. Zero N+1 Queries: Pure SQL joins and aggregations with GROUP BY / COUNT / DISTINCT / AVG / MIN / MAX.
  3. Strictly Parameterized: Eliminates SQL injection risks.
  4. Multi-Tenant User Isolation: Parameterized database connections (target_db).
  5. Safe Pagination / Bounds: All open-ended queries accept safe LIMITs.
"""

import logging
from typing import Dict, Any, List, Optional
from django.db import connections

from User.db_manager import get_current_db

logger = logging.getLogger(__name__)


class DBMSReportingService:
    """
    Read-only DBMS Intelligence Reporting and Analytics service.
    """

    @staticmethod
    def _execute_query(sql: str, params: tuple = (), db_alias: Optional[str] = None) -> List[Dict[str, Any]]:
        """Execute parameterized read-only SQL and return list of row dictionaries."""
        target_db = db_alias or get_current_db() or 'guest_db'
        conn = connections[target_db]
        with conn.cursor() as cursor:
            cursor.execute(sql, params)
            desc = cursor.description
            if not desc:
                return []
            columns = [col[0] for col in desc]
            return [dict(zip(columns, row)) for row in cursor.fetchall()]

    # -------------------------------------------------------------------------
    # 1. Initial ML Uncertainty
    # -------------------------------------------------------------------------
    @classmethod
    def get_initial_ml_uncertainty(cls, limit: int = 100, db_alias: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Find scans where initial RandomForest confidence was below threshold (< 0.75) or flagged uncertain.
        Returns: scan_id, url, initial_class, confidence, threshold, is_confident.
        """
        sql = """
            SELECT
                s.id AS scan_id,
                u.url,
                p.predicted_class AS initial_class,
                p.confidence,
                p.threshold_used,
                p.is_confident
            FROM pari_prediction p
            JOIN pari_scan s ON p.scan_id = s.id
            JOIN pari_url u ON s.url_id = u.id
            WHERE p.confidence < 0.75 OR p.is_confident = 0
            ORDER BY p.confidence ASC
            LIMIT %s;
        """
        return cls._execute_query(sql, (limit,), db_alias=db_alias)

    # -------------------------------------------------------------------------
    # 2. Initial vs Final Disagreement
    # -------------------------------------------------------------------------
    @classmethod
    def get_initial_vs_final_disagreement(cls, limit: int = 100, db_alias: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Show scans where initial RF prediction differed from the corroborated final decision.
        Returns: scan_id, url, initial_rf_class, initial_confidence, final_classification, final_risk, decision_method.
        """
        sql = """
            SELECT
                s.id AS scan_id,
                u.url,
                p.predicted_class AS initial_rf_class,
                p.confidence AS initial_confidence,
                fd.final_classification,
                fd.risk_score AS final_risk,
                fd.decision_method
            FROM pari_final_decision fd
            JOIN pari_scan s ON fd.scan_id = s.id
            JOIN pari_url u ON s.url_id = u.id
            JOIN pari_prediction p ON p.scan_id = s.id
            WHERE p.predicted_class != fd.final_classification
            ORDER BY s.id DESC
            LIMIT %s;
        """
        return cls._execute_query(sql, (limit,), db_alias=db_alias)

    # -------------------------------------------------------------------------
    # 3. Fallback Usage
    # -------------------------------------------------------------------------
    @classmethod
    def get_fallback_usage(cls, limit: int = 100, db_alias: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Show scans where fallback (DeepAnalysis / Nikhil) was triggered and recorded.
        Returns: scan_id, url, service_name, classification, risk_score, risk_level, created_at.
        """
        sql = """
            SELECT
                s.id AS scan_id,
                u.url,
                fb.service_name,
                fb.classification,
                fb.risk_score,
                fb.risk_level,
                fb.created_at
            FROM pari_scan_fallback fb
            JOIN pari_scan s ON fb.scan_id = s.id
            JOIN pari_url u ON s.url_id = u.id
            ORDER BY fb.created_at DESC
            LIMIT %s;
        """
        return cls._execute_query(sql, (limit,), db_alias=db_alias)

    # -------------------------------------------------------------------------
    # 4. AI Usage
    # -------------------------------------------------------------------------
    @classmethod
    def get_ai_usage(cls, limit: int = 100, db_alias: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Show scans where AI was evaluated, required, or dispatched.
        Returns: scan_id, url, ai_required, ai_called, provider, model, status, assessment, confidence.
        """
        sql = """
            SELECT
                s.id AS scan_id,
                u.url,
                ai.ai_required,
                ai.ai_called,
                ai.provider,
                ai.model,
                ai.status,
                ai.assessment,
                ai.confidence
            FROM pari_ai_evidence ai
            JOIN pari_scan s ON ai.scan_id = s.id
            JOIN pari_url u ON s.url_id = u.id
            WHERE ai.ai_required = 1 OR ai.ai_called = 1 OR ai.status != 'NOT_RUN'
            ORDER BY s.id DESC
            LIMIT %s;
        """
        return cls._execute_query(sql, (limit,), db_alias=db_alias)

    # -------------------------------------------------------------------------
    # 5. AI vs Final Disagreement
    # -------------------------------------------------------------------------
    @classmethod
    def get_ai_vs_final_disagreement(cls, limit: int = 100, db_alias: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Show scans where AI structured assessment differed from the authoritative final classification.
        Demonstrates that AI serves strictly as evidence and never dictates the final verdict.
        """
        sql = """
            SELECT
                s.id AS scan_id,
                u.url,
                ai.assessment AS ai_assessment,
                ai.confidence AS ai_confidence,
                fd.final_classification,
                fd.decision_method AS final_decision_method,
                fd.risk_score
            FROM pari_ai_evidence ai
            JOIN pari_scan s ON ai.scan_id = s.id
            JOIN pari_url u ON s.url_id = u.id
            JOIN pari_final_decision fd ON fd.scan_id = s.id
            WHERE ai.assessment IS NOT NULL
              AND UPPER(REPLACE(ai.assessment, 'LIKELY_', '')) != UPPER(fd.final_classification)
            ORDER BY s.id DESC
            LIMIT %s;
        """
        return cls._execute_query(sql, (limit,), db_alias=db_alias)

    # -------------------------------------------------------------------------
    # 6. Evidence Family Count
    # -------------------------------------------------------------------------
    @classmethod
    def get_evidence_family_counts(cls, limit: int = 100, db_alias: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Count distinct evidence families contributing per scan.
        Guarantees that multiple indicators from one collector do not inflate family count.
        """
        sql = """
            SELECT
                s.id AS scan_id,
                u.url,
                COUNT(DISTINCT ev.evidence_family) AS distinct_family_count,
                GROUP_CONCAT(DISTINCT ev.evidence_family ORDER BY ev.evidence_family SEPARATOR ', ') AS families_list
            FROM pari_scan s
            JOIN pari_url u ON s.url_id = u.id
            JOIN pari_evidence_summary ev ON ev.scan_id = s.id
            GROUP BY s.id, u.url
            ORDER BY distinct_family_count DESC, s.id DESC
            LIMIT %s;
        """
        return cls._execute_query(sql, (limit,), db_alias=db_alias)

    # -------------------------------------------------------------------------
    # 7. Threat Indicator Frequency
    # -------------------------------------------------------------------------
    @classmethod
    def get_threat_indicator_frequency(cls, limit: int = 100, db_alias: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Threat indicator frequency report across scans, distinct URLs, and distinct domains.
        """
        sql = """
            SELECT
                ti.id AS indicator_id,
                ti.indicator_type,
                ti.indicator_value,
                ti.severity,
                COUNT(si.id) AS occurrence_count,
                COUNT(DISTINCT s.url_id) AS distinct_url_count,
                COUNT(DISTINCT u.domain_id) AS distinct_domain_count
            FROM pari_threat_indicator ti
            JOIN pari_scan_indicator si ON si.indicator_id = ti.id
            JOIN pari_scan s ON si.scan_id = s.id
            JOIN pari_url u ON s.url_id = u.id
            GROUP BY ti.id, ti.indicator_type, ti.indicator_value, ti.severity
            ORDER BY occurrence_count DESC, ti.id ASC
            LIMIT %s;
        """
        return cls._execute_query(sql, (limit,), db_alias=db_alias)

    # -------------------------------------------------------------------------
    # 8. Threat Indicator Co-occurrence
    # -------------------------------------------------------------------------
    @classmethod
    def get_threat_indicator_cooccurrence(
        cls, scan_id: Optional[int] = None, limit: int = 100, db_alias: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Identify pairs of threat indicators that frequently co-occur in the same scan.
        Optionally filter by scan_id.
        """
        if scan_id is not None:
            sql = """
                SELECT
                    CONCAT(ti1.indicator_type, ':', ti1.indicator_value) AS indicator_a,
                    CONCAT(ti2.indicator_type, ':', ti2.indicator_value) AS indicator_b,
                    COUNT(DISTINCT si1.scan_id) AS cooccurrence_count
                FROM pari_scan_indicator si1
                JOIN pari_scan_indicator si2 ON si1.scan_id = si2.scan_id AND si1.indicator_id < si2.indicator_id
                JOIN pari_threat_indicator ti1 ON si1.indicator_id = ti1.id
                JOIN pari_threat_indicator ti2 ON si2.indicator_id = ti2.id
                WHERE si1.scan_id = %s
                GROUP BY si1.indicator_id, si2.indicator_id, ti1.indicator_type, ti1.indicator_value, ti2.indicator_type, ti2.indicator_value
                ORDER BY cooccurrence_count DESC
                LIMIT %s;
            """
            return cls._execute_query(sql, (scan_id, limit), db_alias=db_alias)
        else:
            sql = """
                SELECT
                    CONCAT(ti1.indicator_type, ':', ti1.indicator_value) AS indicator_a,
                    CONCAT(ti2.indicator_type, ':', ti2.indicator_value) AS indicator_b,
                    COUNT(DISTINCT si1.scan_id) AS cooccurrence_count
                FROM pari_scan_indicator si1
                JOIN pari_scan_indicator si2 ON si1.scan_id = si2.scan_id AND si1.indicator_id < si2.indicator_id
                JOIN pari_threat_indicator ti1 ON si1.indicator_id = ti1.id
                JOIN pari_threat_indicator ti2 ON si2.indicator_id = ti2.id
                GROUP BY si1.indicator_id, si2.indicator_id, ti1.indicator_type, ti1.indicator_value, ti2.indicator_type, ti2.indicator_value
                ORDER BY cooccurrence_count DESC
                LIMIT %s;
            """
            return cls._execute_query(sql, (limit,), db_alias=db_alias)

    # -------------------------------------------------------------------------
    # 9. Domain Intelligence
    # -------------------------------------------------------------------------
    @classmethod
    def get_domain_intelligence_summary(cls, limit: int = 100, db_alias: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Domain-level summary: scan count, distinct URLs, first seen, last seen.
        """
        sql = """
            SELECT
                d.id AS domain_id,
                d.domain_name,
                d.status AS domain_status,
                COUNT(s.id) AS scan_count,
                COUNT(DISTINCT u.id) AS distinct_url_count,
                MIN(s.created_at) AS first_seen,
                MAX(s.created_at) AS last_seen
            FROM pari_domain d
            JOIN pari_url u ON u.domain_id = d.id
            JOIN pari_scan s ON s.url_id = u.id
            GROUP BY d.id, d.domain_name, d.status
            ORDER BY scan_count DESC, d.domain_name ASC
            LIMIT %s;
        """
        return cls._execute_query(sql, (limit,), db_alias=db_alias)

    # -------------------------------------------------------------------------
    # 10. Mixed-History Domains
    # -------------------------------------------------------------------------
    @classmethod
    def get_mixed_history_domains(cls, limit: int = 100, db_alias: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Find domains with more than one historical classification across prior scans.
        """
        sql = """
            SELECT
                d.id AS domain_id,
                d.domain_name,
                COUNT(DISTINCT COALESCE(fd.final_classification, fb.classification, p.predicted_class)) AS distinct_class_count,
                GROUP_CONCAT(DISTINCT COALESCE(fd.final_classification, fb.classification, p.predicted_class) ORDER BY COALESCE(fd.final_classification, fb.classification, p.predicted_class) SEPARATOR ', ') AS classification_distribution,
                COUNT(s.id) AS total_scans
            FROM pari_domain d
            JOIN pari_url u ON u.domain_id = d.id
            JOIN pari_scan s ON s.url_id = u.id
            LEFT JOIN pari_final_decision fd ON fd.scan_id = s.id
            LEFT JOIN pari_scan_fallback fb ON fb.scan_id = s.id
            LEFT JOIN pari_prediction p ON p.scan_id = s.id
            GROUP BY d.id, d.domain_name
            HAVING distinct_class_count > 1
            ORDER BY distinct_class_count DESC, total_scans DESC
            LIMIT %s;
        """
        return cls._execute_query(sql, (limit,), db_alias=db_alias)

    # -------------------------------------------------------------------------
    # 11. Suspicious-Feature Combinations
    # -------------------------------------------------------------------------
    @classmethod
    def get_suspicious_feature_combinations(cls, limit: int = 100, db_alias: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Find scans exhibiting suspicious structural PARI feature combinations (e.g. raw IP without HTTPS, or URL shortener with abnormal syntax).
        """
        sql = """
            SELECT
                s.id AS scan_id,
                u.url,
                sf.have_ip,
                sf.secure_http,
                sf.shortened,
                sf.abnormal_url,
                sf.url_len,
                sf.special_chars_count,
                COALESCE(fd.final_classification, p.predicted_class) AS classification,
                COALESCE(fd.risk_score, p.risk_score) AS risk_score
            FROM pari_scan_features sf
            JOIN pari_scan s ON sf.scan_id = s.id
            JOIN pari_url u ON s.url_id = u.id
            LEFT JOIN pari_prediction p ON p.scan_id = s.id
            LEFT JOIN pari_final_decision fd ON fd.scan_id = s.id
            WHERE (sf.have_ip = 1 AND sf.secure_http = 0)
               OR (sf.shortened = 1 AND sf.abnormal_url = 1)
               OR (sf.have_ip = 1 AND sf.abnormal_url = 1)
            ORDER BY s.id DESC
            LIMIT %s;
        """
        return cls._execute_query(sql, (limit,), db_alias=db_alias)

    # -------------------------------------------------------------------------
    # 12. SQL_HISTORY Usage
    # -------------------------------------------------------------------------
    @classmethod
    def get_sql_history_usage(cls, limit: int = 100, db_alias: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Find scans where the SQL_HISTORY collector found historical intelligence matches.
        """
        sql = """
            SELECT
                s.id AS scan_id,
                u.url,
                ev.evidence_family,
                ev.status,
                ev.detected,
                ev.match_found,
                ev.evidence_count,
                ev.summary,
                ev.source_component,
                s.created_at
            FROM pari_evidence_summary ev
            JOIN pari_scan s ON ev.scan_id = s.id
            JOIN pari_url u ON s.url_id = u.id
            WHERE ev.evidence_family = 'SQL_HISTORY'
              AND (ev.match_found = 1 OR ev.detected = 1)
            ORDER BY s.id DESC
            LIMIT %s;
        """
        return cls._execute_query(sql, (limit,), db_alias=db_alias)

    # -------------------------------------------------------------------------
    # 13. Provenance Report
    # -------------------------------------------------------------------------
    @classmethod
    def get_provenance_report(cls, scan_id: int, db_alias: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Detailed evidence provenance report for a single scan.
        Combines high-level evidence family sources and granular threat indicators with detection reasons.
        """
        sql = """
            SELECT
                evidence_family,
                source_component,
                'EVIDENCE_FAMILY' AS evidence_kind,
                status,
                severity,
                summary AS description,
                match_found,
                detected,
                evidence_count
            FROM pari_evidence_summary
            WHERE scan_id = %s

            UNION ALL

            SELECT
                ti.indicator_type AS evidence_family,
                si.source_component,
                'THREAT_INDICATOR' AS evidence_kind,
                'DETECTED' AS status,
                COALESCE(si.severity, ti.severity) AS severity,
                CONCAT(ti.indicator_value, CASE WHEN si.reason != '' THEN CONCAT(' (', si.reason, ')') ELSE '' END) AS description,
                1 AS match_found,
                1 AS detected,
                1 AS evidence_count
            FROM pari_scan_indicator si
            JOIN pari_threat_indicator ti ON si.indicator_id = ti.id
            WHERE si.scan_id = %s
            ORDER BY evidence_kind, evidence_family;
        """
        return cls._execute_query(sql, (scan_id, scan_id), db_alias=db_alias)

    # -------------------------------------------------------------------------
    # 14. Final Risk Distribution
    # -------------------------------------------------------------------------
    @classmethod
    def get_final_risk_distribution(cls, db_alias: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Aggregate final risk levels (LOW, MEDIUM, HIGH, CRITICAL) from authoritative final decisions.
        """
        sql = """
            SELECT
                risk_level,
                COUNT(*) AS scan_count,
                ROUND(AVG(risk_score), 4) AS avg_risk_score,
                MIN(risk_score) AS min_risk_score,
                MAX(risk_score) AS max_risk_score
            FROM pari_final_decision
            GROUP BY risk_level
            ORDER BY FIELD(risk_level, 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL');
        """
        return cls._execute_query(sql, (), db_alias=db_alias)

    # -------------------------------------------------------------------------
    # 15. Full Scan Investigation Summary
    # -------------------------------------------------------------------------
    @classmethod
    def get_full_scan_investigation_summary(
        cls, scan_id: Optional[int] = None, limit: int = 100, db_alias: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Compact one-row scan investigation overview joining:
        pari_scan, pari_url, pari_domain, pari_prediction, pari_scan_fallback,
        pari_ai_evidence, and pari_final_decision.
        """
        if scan_id is not None:
            sql = """
                SELECT
                    s.id AS scan_id,
                    u.url,
                    d.domain_name,
                    s.status AS scan_status,
                    s.created_at,
                    p.predicted_class AS initial_rf_class,
                    p.confidence AS initial_rf_confidence,
                    p.is_confident AS initial_rf_is_confident,
                    fb.service_name AS fallback_service,
                    fb.classification AS fallback_classification,
                    fb.risk_score AS fallback_risk_score,
                    fb.risk_level AS fallback_risk_level,
                    ai.status AS ai_status,
                    ai.provider AS ai_provider,
                    ai.assessment AS ai_assessment,
                    ai.confidence AS ai_confidence,
                    fd.final_classification,
                    fd.risk_score AS final_risk_score,
                    fd.risk_level AS final_risk_level,
                    fd.decision_method AS final_decision_method,
                    fd.decision_status AS final_decision_status,
                    fd.corroboration_strength,
                    fd.evidence_family_count,
                    fd.conflict_detected
                FROM pari_scan s
                JOIN pari_url u ON s.url_id = u.id
                LEFT JOIN pari_domain d ON u.domain_id = d.id
                LEFT JOIN pari_prediction p ON p.scan_id = s.id
                LEFT JOIN pari_scan_fallback fb ON fb.scan_id = s.id
                LEFT JOIN pari_ai_evidence ai ON ai.scan_id = s.id
                LEFT JOIN pari_final_decision fd ON fd.scan_id = s.id
                WHERE s.id = %s;
            """
            return cls._execute_query(sql, (scan_id,), db_alias=db_alias)
        else:
            sql = """
                SELECT
                    s.id AS scan_id,
                    u.url,
                    d.domain_name,
                    s.status AS scan_status,
                    s.created_at,
                    p.predicted_class AS initial_rf_class,
                    p.confidence AS initial_rf_confidence,
                    p.is_confident AS initial_rf_is_confident,
                    fb.service_name AS fallback_service,
                    fb.classification AS fallback_classification,
                    fb.risk_score AS fallback_risk_score,
                    fb.risk_level AS fallback_risk_level,
                    ai.status AS ai_status,
                    ai.provider AS ai_provider,
                    ai.assessment AS ai_assessment,
                    ai.confidence AS ai_confidence,
                    fd.final_classification,
                    fd.risk_score AS final_risk_score,
                    fd.risk_level AS final_risk_level,
                    fd.decision_method AS final_decision_method,
                    fd.decision_status AS final_decision_status,
                    fd.corroboration_strength,
                    fd.evidence_family_count,
                    fd.conflict_detected
                FROM pari_scan s
                JOIN pari_url u ON s.url_id = u.id
                LEFT JOIN pari_domain d ON u.domain_id = d.id
                LEFT JOIN pari_prediction p ON p.scan_id = s.id
                LEFT JOIN pari_scan_fallback fb ON fb.scan_id = s.id
                LEFT JOIN pari_ai_evidence ai ON ai.scan_id = s.id
                LEFT JOIN pari_final_decision fd ON fd.scan_id = s.id
                ORDER BY s.id DESC
                LIMIT %s;
            """
            return cls._execute_query(sql, (limit,), db_alias=db_alias)
