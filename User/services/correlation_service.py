"""
SQL-backed correlation queries over one tenant database.

Every method takes an optional ``db`` alias; when omitted the request's tenant
alias (``UserDatabaseMiddleware``) is used, falling back to the guest DB. No
method can reach another tenant's database.
"""

from django.db.models import Count, Q

from User.models import Domain, IP, Scan, ThreatIndicator, URL

MALICIOUS_CLASSES = ('Phishing', 'Malware', 'Defacement')


def _db(db=None):
    from User.db_manager import get_current_db
    return db or get_current_db() or 'guest_db'


def _malicious_scan_q(prefix=''):
    """Scan considered malicious: authoritative final decision, else initial RF."""
    return (Q(**{f'{prefix}final_decision__final_classification__in': MALICIOUS_CLASSES})
            | (Q(**{f'{prefix}final_decision__isnull': True})
               & Q(**{f'{prefix}prediction__predicted_class__in': MALICIOUS_CLASSES})))


class CorrelationService:
    """Service for SQL-backed cybersecurity correlation queries"""

    @staticmethod
    def get_urls_by_domain(domain_id, db=None):
        return URL.objects.using(_db(db)).filter(domain_id=domain_id).prefetch_related('scans__prediction')

    @staticmethod
    def get_domains_by_ip(ip_id, db=None):
        """Domains whose scans resolved to the given IP (IP -> domain correlation)."""
        alias = _db(db)
        return Domain.objects.using(alias).filter(urls__scans__ip_id=ip_id).distinct()

    @staticmethod
    def get_ips_by_domain(domain_id, db=None):
        """Validated public IPs observed for a domain (domain -> IP correlation)."""
        alias = _db(db)
        return (IP.objects.using(alias)
                .filter(scans__url__domain_id=domain_id)
                .annotate(scan_count=Count('scans', distinct=True))
                .order_by('-scan_count'))

    @staticmethod
    def get_ips_by_malicious_urls(limit=10, db=None):
        """IPs associated with scans whose outcome was malicious, most first."""
        alias = _db(db)
        return (IP.objects.using(alias)
                .annotate(malicious_count=Count('scans', filter=_malicious_scan_q('scans__'), distinct=True),
                          domain_count=Count('scans__url__domain', distinct=True))
                .filter(malicious_count__gt=0)
                .order_by('-malicious_count', '-risk_score')[:limit])

    @staticmethod
    def get_domain_scan_history(domain_id, db=None):
        return Scan.objects.using(_db(db)).filter(url__domain_id=domain_id) \
            .select_related('prediction').order_by('-created_at')

    @staticmethod
    def get_domain_prediction_changes(domain_id, db=None):
        changes = []
        last_class = None
        for scan in CorrelationService.get_domain_scan_history(domain_id, db=db):
            pred = getattr(scan, 'prediction', None)
            if pred and pred.predicted_class != last_class:
                changes.append({
                    'scan_id': scan.id,
                    'timestamp': scan.created_at,
                    'predicted_class': pred.predicted_class,
                    'confidence': pred.confidence,
                    'url': scan.url.url,
                })
                last_class = pred.predicted_class
        return changes

    @staticmethod
    def get_domain_threat_indicators(domain_id, db=None):
        alias = _db(db)
        scans = Scan.objects.using(alias).filter(url__domain_id=domain_id)
        return ThreatIndicator.objects.using(alias).filter(scanindicator__scan__in=scans) \
            .distinct().order_by('-severity')

    @staticmethod
    def get_urls_sharing_infrastructure(url_id, limit=20, db=None):
        """URLs on the same registered domain or resolving to the same IP."""
        alias = _db(db)
        url = URL.objects.using(alias).get(id=url_id)
        ip_ids = Scan.objects.using(alias).filter(url=url, ip__isnull=False).values_list('ip_id', flat=True)
        query = Q(scans__ip_id__in=list(ip_ids))
        if url.domain_id:
            query |= Q(domain_id=url.domain_id)
        return URL.objects.using(alias).filter(query).exclude(id=url_id).distinct()[:limit]

    @staticmethod
    def get_domain_risk_history(domain_id, db=None):
        history = []
        for scan in CorrelationService.get_domain_scan_history(domain_id, db=db):
            pred = getattr(scan, 'prediction', None)
            if pred:
                history.append({
                    'scan_id': scan.id,
                    'timestamp': scan.created_at,
                    'risk_score': pred.risk_score,
                    'predicted_class': pred.predicted_class,
                    'confidence': pred.confidence,
                })
        return history

    @staticmethod
    def calculate_domain_aggregate_risk(domain_id, db=None):
        scans = Scan.objects.using(_db(db)).filter(url__domain_id=domain_id, status='COMPLETED') \
            .select_related('prediction')
        predictions = [p for p in (getattr(s, 'prediction', None) for s in scans) if p is not None]
        if not predictions:
            return None
        malicious_count = sum(1 for p in predictions if p.predicted_class in MALICIOUS_CLASSES)
        return {
            'domain_id': domain_id,
            'average_risk_score': sum(p.risk_score for p in predictions) / len(predictions),
            'max_risk_score': max(p.risk_score for p in predictions),
            'scan_count': len(predictions),
            'malicious_count': malicious_count,
            'malicious_percentage': malicious_count / len(predictions) * 100,
        }

    @staticmethod
    def get_related_security_data(domain_id, db=None):
        alias = _db(db)
        domain = Domain.objects.using(alias).get(id=domain_id)
        return {
            'domain': {
                'id': domain.id,
                'name': domain.domain_name,
                'tld': domain.tld,
                'status': domain.status,
                'risk_score': domain.risk_score,
                'last_scanned': domain.last_scanned,
            },
            'urls': list(CorrelationService.get_urls_by_domain(domain_id, db=alias).values(
                'id', 'url', 'source', 'baseline_label')[:20]),
            'scan_history': list(CorrelationService.get_domain_scan_history(domain_id, db=alias).values(
                'id', 'status', 'created_at')[:20]),
            'observed_ips': [
                {'ip': ip.ip_address, 'status': ip.status, 'risk_score': ip.risk_score, 'scan_count': ip.scan_count}
                for ip in CorrelationService.get_ips_by_domain(domain_id, db=alias)[:20]
            ],
            'threat_indicators': list(CorrelationService.get_domain_threat_indicators(domain_id, db=alias).values(
                'id', 'indicator_type', 'indicator_value', 'severity')[:20]),
            'prediction_changes': CorrelationService.get_domain_prediction_changes(domain_id, db=alias)[:10],
            'risk_history': CorrelationService.get_domain_risk_history(domain_id, db=alias)[:20],
            'aggregate_risk': CorrelationService.calculate_domain_aggregate_risk(domain_id, db=alias),
        }
