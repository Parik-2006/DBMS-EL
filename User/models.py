from django.db import models
from django.contrib.auth.models import User
from django.core.validators import URLValidator, validate_ipv4_address
from django.db.models import Avg, Max, Min, Count

class AnalystReview(models.Model):
    """Analyst review record for Unknown/Needs Review cases"""
    
    VALIDATION_CHOICES = [
        ('Benign', 'Benign'),
        ('Phishing', 'Phishing'),
        ('Malware', 'Malware'),
        ('Defacement', 'Defacement'),
        ('Still Unknown', 'Still Unknown'),
    ]
    
    VALIDATED_CHOICES = [
        ('VALIDATED', 'Validated for future training'),
        ('NOT_VALIDATED', 'Not validated'),
    ]
    
    scan = models.OneToOneField('Scan', on_delete=models.CASCADE, related_name='analyst_review')
    reviewer = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, db_constraint=False)
    reviewed_at = models.DateTimeField(auto_now_add=True)
    final_label = models.CharField(max_length=20, choices=VALIDATION_CHOICES)
    review_notes = models.TextField(blank=True, null=True)
    validation_status = models.CharField(max_length=20, choices=VALIDATED_CHOICES, default='NOT_VALIDATED')
    
    class Meta:
        db_table = 'pari_analyst_review'
        
    def __str__(self):
        return f"Review for Scan {self.scan.id}: {self.final_label}"

class MaliciousBot(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True, db_constraint=False)
    url = models.TextField()
    bot = models.CharField(max_length=90, null=True, blank=True)
    prediction = models.TextField(null=True, blank=True)
    prediction_type = models.CharField(max_length=50, null=True, blank=True)
    confidence = models.CharField(max_length=50, null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True, null=True)

    
    def __str__(self):
        return f"{self.user} - {self.url} ({self.prediction_type})" if self.user else f"Guest - {self.url}"
    
    class Meta:
        ordering = ['-timestamp']


class Domain(models.Model):
    """Normalized domain storage for correlation"""
    DOMAIN_STATUS_CHOICES = [
        ('BENIGN', 'Benign'),
        ('SUSPICIOUS', 'Suspicious'),
        ('MALICIOUS', 'Malicious'),
        ('UNKNOWN', 'Unknown'),
    ]
    
    domain_name = models.CharField(max_length=255, unique=True, db_index=True)
    tld = models.CharField(max_length=10, null=True, blank=True)
    status = models.CharField(max_length=20, choices=DOMAIN_STATUS_CHOICES, default='UNKNOWN', db_index=True)
    risk_score = models.FloatField(default=0.0)
    last_scanned = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'pari_domain'
        indexes = [
            models.Index(fields=['domain_name']),
            models.Index(fields=['status']),
            models.Index(fields=['risk_score']),
        ]
    
    def __str__(self):
        return f"{self.domain_name} ({self.status})"


class URL(models.Model):
    """Normalized URL storage for baseline and scan data"""
    URL_SOURCE_CHOICES = [
        ('BASELINE', 'Baseline Dataset'),
        ('USER_SCAN', 'User Scan'),
        ('CORRELATION', 'Correlation Analysis'),
    ]
    
    url = models.CharField(max_length=500, unique=True, db_index=True)
    domain = models.ForeignKey(Domain, on_delete=models.CASCADE, related_name='urls', null=True, blank=True)
    source = models.CharField(max_length=20, choices=URL_SOURCE_CHOICES, default='USER_SCAN')
    baseline_label = models.CharField(
        max_length=20, 
        choices=[('benign', 'Benign'), ('defacement', 'Defacement'), ('phishing', 'Phishing'), ('malware', 'Malware')],
        null=True, 
        blank=True,
        help_text='Only populated for baseline dataset URLs'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'pari_url'
        indexes = [
            models.Index(fields=['url']),
            models.Index(fields=['source']),
            models.Index(fields=['domain']),
        ]
    
    def __str__(self):
        return f"{self.url[:50]} ({self.source})"


class IP(models.Model):
    """IP address storage for correlation analysis"""
    ip_address = models.GenericIPAddressField(unique=True, db_index=True)
    status = models.CharField(
        max_length=20,
        choices=[('BENIGN', 'Benign'), ('SUSPICIOUS', 'Suspicious'), ('MALICIOUS', 'Malicious'), ('UNKNOWN', 'Unknown')],
        default='UNKNOWN',
        db_index=True
    )
    country = models.CharField(max_length=100, null=True, blank=True)
    risk_score = models.FloatField(default=0.0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'pari_ip'
        verbose_name_plural = 'IPs'
        indexes = [
            models.Index(fields=['ip_address']),
            models.Index(fields=['status']),
            models.Index(fields=['risk_score']),
        ]
    
    def __str__(self):
        return f"{self.ip_address} ({self.status})"


class Scan(models.Model):
    """Scan record - represents a single URL analysis request"""
    SCAN_STATUS_CHOICES = [
        ('CONFIDENT', 'Confident - ML prediction sufficient'),
        ('UNCERTAIN', 'Uncertain - routing to fallback'),
        ('DEEP_ANALYSIS', 'Deep analysis in progress'),
        ('COMPLETED', 'Completed - result stored'),
        ('ERROR', 'Error during scan'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='scans', null=True, blank=True, db_constraint=False)
    url = models.ForeignKey(URL, on_delete=models.CASCADE, related_name='scans')
    status = models.CharField(max_length=20, choices=SCAN_STATUS_CHOICES, db_index=True)
    
    initial_model = models.CharField(max_length=50, default='RandomForest', help_text='ML model used for initial prediction')
    fallback_model = models.CharField(max_length=50, null=True, blank=True, help_text='Fallback model if used')
    
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'pari_scan'
        indexes = [
            models.Index(fields=['status']),
            models.Index(fields=['user']),
            models.Index(fields=['created_at']),
        ]
        ordering = ['-created_at']
    
    def __str__(self):
        return f"Scan {self.id} - {self.url.url[:40]} ({self.status})"


class Prediction(models.Model):
    """ML prediction record - stores model output and confidence"""
    PREDICTION_CLASS_CHOICES = [
        ('Benign', 'Benign'),
        ('Phishing', 'Phishing'),
        ('Malware', 'Malware'),
        ('Defacement', 'Defacement'),
        ('Unknown', 'Unknown'),
    ]
    
    scan = models.OneToOneField(Scan, on_delete=models.CASCADE, related_name='prediction')
    model_name = models.CharField(max_length=50)
    predicted_class = models.CharField(max_length=20, choices=PREDICTION_CLASS_CHOICES, db_index=True)
    confidence = models.FloatField(help_text='Confidence score 0.0-1.0')
    risk_score = models.FloatField(help_text='Risk score 0.0-1.0')
    
    probabilities = models.JSONField(
        default=dict,
        help_text='Model output probabilities for each class',
        null=True,
        blank=True
    )
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'pari_prediction'
        indexes = [
            models.Index(fields=['predicted_class']),
            models.Index(fields=['confidence']),
            models.Index(fields=['risk_score']),
        ]
    
    def __str__(self):
        return f"Prediction: {self.predicted_class} ({self.confidence:.2%})"


class ThreatIndicator(models.Model):
    """Threat indicators extracted from URLs/domains/IPs"""
    INDICATOR_TYPE_CHOICES = [
        ('IP_ADDRESS', 'IP Address'),
        ('DOMAIN', 'Domain'),
        ('URL_LENGTH', 'URL Length Anomaly'),
        ('SPECIAL_CHARS', 'Special Characters'),
        ('SHORTENER', 'URL Shortener'),
        ('SSL_CERTIFICATE', 'SSL Certificate Issue'),
        ('GEOLOCATION', 'Suspicious Geolocation'),
        ('REPUTATION', 'Low Reputation Score'),
        ('OTHER', 'Other'),
    ]
    
    SEVERITY_CHOICES = [
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]
    
    indicator_type = models.CharField(max_length=30, choices=INDICATOR_TYPE_CHOICES, db_index=True)
    indicator_value = models.CharField(max_length=255)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default='MEDIUM')
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'pari_threat_indicator'
        unique_together = ('indicator_type', 'indicator_value')
        indexes = [
            models.Index(fields=['indicator_type']),
            models.Index(fields=['severity']),
        ]
    
    def __str__(self):
        return f"{self.indicator_type}: {self.indicator_value} ({self.severity})"


class ScanIndicator(models.Model):
    """Junction table for many-to-many relationship between Scan and ThreatIndicator"""
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='threat_indicators')
    indicator = models.ForeignKey(ThreatIndicator, on_delete=models.CASCADE)
    detected_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'pari_scan_indicator'
        unique_together = ('scan', 'indicator')
        indexes = [
            models.Index(fields=['scan']),
            models.Index(fields=['indicator']),
        ]
    
    def __str__(self):
        return f"Scan {self.scan.id} - {self.indicator.indicator_type}"


class UserDatabaseRegistry(models.Model):
    """
    Control database registry mapping users to their isolated MySQL databases.
    Stored in maliciousbot_core.
    """
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('suspended', 'Suspended'),
        ('archived', 'Archived'),
    ]
    
    user_id = models.IntegerField(unique=True, db_index=True)
    username = models.CharField(max_length=150, db_index=True)
    database_name = models.CharField(max_length=100, unique=True, db_index=True)
    status = models.CharField(max_length=30, choices=STATUS_CHOICES, default='active')
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'user_database_registry'
        verbose_name = 'User Database Registry'
        verbose_name_plural = 'User Database Registries'

    def __str__(self):
        return f"User {self.username} (ID: {self.user_id}) -> {self.database_name}"


class HistoryClearEvent(models.Model):
    """
    Non-destructive history visibility reset record.
    Stored in per-user database. Scans prior to cleared_at are hidden from the UI,
    retaining all underlying database records permanently.
    """
    user_id = models.IntegerField(null=True, blank=True, db_index=True)
    cleared_at = models.DateTimeField(db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'history_clear_events'
        ordering = ['-cleared_at']

    def __str__(self):
        return f"History clear for user {self.user_id} at {self.cleared_at}"