from django.db.models import Q, Count, Avg
from User.models import Scan, Prediction, URL, Domain, IP, ScanIndicator, ThreatIndicator

class CorrelationService:
    """Service for SQL-backed cybersecurity correlation queries"""
    
    @staticmethod
    def get_urls_by_domain(domain_id):
        """Get all URLs belonging to a domain"""
        return URL.objects.filter(domain_id=domain_id).prefetch_related('scans__prediction')
    
    @staticmethod
    def get_domains_by_ip(ip_id):
        """Get all domains associated with an IP"""
        scans_with_ip = Scan.objects.filter(ip_id=ip_id)
        urls = URL.objects.filter(scans__in=scans_with_ip).distinct()
        domains = Domain.objects.filter(urls__in=urls).distinct()
        return domains
    
    @staticmethod
    def get_ips_by_malicious_urls(limit=10):
        """Get IPs associated with multiple malicious URLs"""
        # This query requires IP model to have a relation to Scan
        # For now, return empty queryset
        return IP.objects.none()
    
    @staticmethod
    def get_domain_scan_history(domain_id):
        """Get complete scan history for a domain"""
        scans = Scan.objects.filter(
            url__domain_id=domain_id
        ).select_related('prediction').order_by('-created_at')
        return scans
    
    @staticmethod
    def get_domain_prediction_changes(domain_id):
        """Get prediction changes over time for a domain"""
        scans = Scan.objects.filter(
            url__domain_id=domain_id
        ).select_related('prediction').order_by('-created_at')
        
        changes = []
        last_class = None
        
        for scan in scans:
            pred = getattr(scan, 'prediction', None)
            if pred:
                if pred.predicted_class != last_class:
                    changes.append({
                        'scan_id': scan.id,
                        'timestamp': scan.created_at,
                        'predicted_class': pred.predicted_class,
                        'confidence': pred.confidence,
                        'url': scan.url.url
                    })
                    last_class = pred.predicted_class
        
        return changes
    
    @staticmethod
    def get_domain_threat_indicators(domain_id):
        """Get threat indicators associated with a domain"""
        scans = Scan.objects.filter(url__domain_id=domain_id)
        indicators = ThreatIndicator.objects.filter(
            scanindicator__scan__in=scans
        ).distinct().order_by('-severity')
        return indicators
    
    @staticmethod
    def get_urls_sharing_infrastructure(url_id, limit=20):
        """Get URLs sharing suspicious infrastructure with a given URL"""
        url = URL.objects.get(id=url_id)
        
        if not url.domain:
            return []
        
        same_domain_urls = URL.objects.filter(
            domain=url.domain
        ).exclude(id=url_id)[:limit]
        
        return same_domain_urls
    
    @staticmethod
    def get_domain_risk_history(domain_id):
        """Get risk score history for a domain"""
        scans = Scan.objects.filter(
            url__domain_id=domain_id
        ).select_related('prediction').order_by('-created_at')
        
        history = []
        for scan in scans:
            pred = getattr(scan, 'prediction', None)
            if pred:
                history.append({
                    'scan_id': scan.id,
                    'timestamp': scan.created_at,
                    'risk_score': pred.risk_score,
                    'predicted_class': pred.predicted_class,
                    'confidence': pred.confidence
                })
        
        return history
    
    @staticmethod
    def calculate_domain_aggregate_risk(domain_id):
        """Calculate aggregate risk score for a domain"""
        scans = Scan.objects.filter(
            url__domain_id=domain_id,
            status='COMPLETED'
        ).select_related('prediction')
        
        if not scans.exists():
            return None
        
        predictions = [getattr(s, 'prediction', None) for s in scans]
        predictions = [p for p in predictions if p is not None]
        
        if not predictions:
            return None
        
        avg_risk = sum(p.risk_score for p in predictions) / len(predictions)
        max_risk = max(p.risk_score for p in predictions)
        
        malicious_count = sum(
            1 for p in predictions 
            if p.predicted_class in ['Phishing', 'Malware', 'Defacement']
        )
        
        return {
            'domain_id': domain_id,
            'average_risk_score': avg_risk,
            'max_risk_score': max_risk,
            'scan_count': len(predictions),
            'malicious_count': malicious_count,
            'malicious_percentage': (malicious_count / len(predictions) * 100) if predictions else 0
        }
    
    @staticmethod
    def get_related_security_data(domain_id):
        """Get comprehensive related security information for a domain"""
        domain = Domain.objects.get(id=domain_id)
        
        return {
            'domain': {
                'id': domain.id,
                'name': domain.domain_name,
                'status': domain.status,
                'risk_score': domain.risk_score,
                'last_scanned': domain.last_scanned
            },
            'urls': list(CorrelationService.get_urls_by_domain(domain_id).values(
                'id', 'url', 'source', 'baseline_label'
            )[:20]),
            'scan_history': list(CorrelationService.get_domain_scan_history(domain_id).values(
                'id', 'status', 'created_at'
            )[:20]),
            'threat_indicators': list(CorrelationService.get_domain_threat_indicators(domain_id).values(
                'id', 'indicator_type', 'indicator_value', 'severity'
            )[:20]),
            'prediction_changes': CorrelationService.get_domain_prediction_changes(domain_id)[:10],
            'risk_history': CorrelationService.get_domain_risk_history(domain_id)[:20],
            'aggregate_risk': CorrelationService.calculate_domain_aggregate_risk(domain_id)
        }
