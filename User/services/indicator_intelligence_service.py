"""
Indicator Intelligence Service — Phase 8
Provides rich SQL-queryable intelligence over the Threat Indicator Historical Graph:
  pari_threat_indicator (indicator definition)
          ↓
  pari_scan_indicator (scan-to-indicator junction event)
          ↓
  pari_scan (scan event)

Capabilities:
  1. Indicator frequency & occurrence tracking across scans.
  2. Co-occurring indicators (indicators appearing together in the same scan).
  3. Domain-level indicator repetition analytics.
  4. Indicator severity distributions.
  5. URL and domain associations per indicator.
"""

import logging
from typing import Optional, Dict, Any, List
from django.db.models import Count, Q

from User.db_manager import get_current_db

logger = logging.getLogger(__name__)


class IndicatorIntelligenceService:
    """
    Historical intelligence queries over Threat Indicators and Scan Associations.
    """

    @classmethod
    def get_indicator_history(
        cls,
        indicator_type: str,
        indicator_value: str,
        db_alias: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Retrieve comprehensive historical intelligence for a specific indicator.
        """
        target_db = db_alias or get_current_db() or 'guest_db'
        from User.models import ThreatIndicator, ScanIndicator, Scan

        indicator_obj = (
            ThreatIndicator.objects.using(target_db)
            .filter(indicator_type=indicator_type, indicator_value=indicator_value)
            .first()
        )

        if not indicator_obj:
            return {
                "exists": False,
                "indicator_type": indicator_type,
                "indicator_value": indicator_value,
                "observation_count": 0,
                "scan_ids": [],
                "distinct_domains": [],
                "distinct_urls": [],
                "severity": None,
                "first_seen": None,
                "last_seen": None,
            }

        scan_links = (
            ScanIndicator.objects.using(target_db)
            .filter(indicator=indicator_obj)
            .select_related('scan__url__domain')
            .order_by('detected_at')
        )

        scan_ids = []
        domains = set()
        urls = set()
        first_seen = None
        last_seen = None

        for link in scan_links:
            s = link.scan
            scan_ids.append(s.id)
            if s.url:
                urls.add(s.url.url)
                if s.url.domain:
                    domains.add(s.url.domain.domain_name)
            if first_seen is None or link.detected_at < first_seen:
                first_seen = link.detected_at
            if last_seen is None or link.detected_at > last_seen:
                last_seen = link.detected_at

        return {
            "exists": True,
            "indicator_type": indicator_obj.indicator_type,
            "indicator_value": indicator_obj.indicator_value,
            "severity": indicator_obj.severity,
            "observation_count": len(scan_ids),
            "scan_ids": scan_ids,
            "distinct_domain_count": len(domains),
            "distinct_domains": sorted(list(domains)),
            "distinct_url_count": len(urls),
            "distinct_urls": sorted(list(urls))[:20],
            "first_seen": first_seen.isoformat() if first_seen else None,
            "last_seen": last_seen.isoformat() if last_seen else None,
        }

    @classmethod
    def get_frequent_indicators(cls, limit: int = 20, db_alias: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        List the most frequently observed indicators across all scans.
        """
        target_db = db_alias or get_current_db() or 'guest_db'
        from User.models import ThreatIndicator

        top_inds = (
            ThreatIndicator.objects.using(target_db)
            .annotate(scan_count=Count('scanindicator'))
            .filter(scan_count__gt=0)
            .order_by('-scan_count')[:limit]
        )

        return [
            {
                "type": ind.indicator_type,
                "value": ind.indicator_value,
                "severity": ind.severity,
                "scan_count": ind.scan_count,
            }
            for ind in top_inds
        ]

    @classmethod
    def get_indicators_for_domain(
        cls, domain_name: str, min_occurrences: int = 1, db_alias: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        List threat indicators associated with scans of a specific domain.
        """
        target_db = db_alias or get_current_db() or 'guest_db'
        from User.models import ThreatIndicator

        indicators = (
            ThreatIndicator.objects.using(target_db)
            .filter(scanindicator__scan__url__domain__domain_name__iexact=domain_name.strip())
            .annotate(occurrence_count=Count('scanindicator'))
            .filter(occurrence_count__gte=min_occurrences)
            .order_by('-occurrence_count')
        )

        return [
            {
                "type": ind.indicator_type,
                "value": ind.indicator_value,
                "severity": ind.severity,
                "occurrences": ind.occurrence_count,
                "is_repeated": bool(ind.occurrence_count > 1),
            }
            for ind in indicators
        ]

    @classmethod
    def get_cooccurring_indicators(
        cls, indicator_type: str, indicator_value: str, db_alias: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Find other indicators that were observed in the same scans as this indicator.
        """
        target_db = db_alias or get_current_db() or 'guest_db'
        from User.models import ThreatIndicator, ScanIndicator

        # Find scans containing the target indicator
        scan_ids = list(
            ScanIndicator.objects.using(target_db)
            .filter(indicator__indicator_type=indicator_type, indicator__indicator_value=indicator_value)
            .values_list('scan_id', flat=True)
        )

        if not scan_ids:
            return []

        # Find other indicators in those scans
        co_inds = (
            ThreatIndicator.objects.using(target_db)
            .filter(scanindicator__scan_id__in=scan_ids)
            .exclude(indicator_type=indicator_type, indicator_value=indicator_value)
            .annotate(cooccurrence_count=Count('scanindicator'))
            .order_by('-cooccurrence_count')[:15]
        )

        return [
            {
                "type": ind.indicator_type,
                "value": ind.indicator_value,
                "severity": ind.severity,
                "cooccurrence_count": ind.cooccurrence_count,
            }
            for ind in co_inds
        ]

    @classmethod
    def get_severity_distribution(cls, db_alias: Optional[str] = None) -> Dict[str, int]:
        """
        Get the distribution of observed indicator occurrences by severity level.
        """
        target_db = db_alias or get_current_db() or 'guest_db'
        from User.models import ScanIndicator

        dist = (
            ScanIndicator.objects.using(target_db)
            .values('indicator__severity')
            .annotate(count=Count('id'))
        )

        result = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for item in dist:
            sev = item.get('indicator__severity')
            if sev in result:
                result[sev] = item['count']
        return result
