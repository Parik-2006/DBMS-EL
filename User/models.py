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
    """ML prediction record - stores the INITIAL RandomForest model output.

    Phase 3 invariant:
        - model_name must always be 'RandomForest' for new scans.
        - This record must NEVER be overwritten by fallback/DeepAnalysis.
        - Fallback results live in ScanFallbackResult (pari_scan_fallback).

    Historical rows created before Phase 3 may still carry legacy values
    (model_name='DeepAnalysis', mixed fields). They are not backfilled.
    """
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

    # Phase 3 additions — nullable for backward-compat with pre-Phase-3 rows.
    threshold_used = models.FloatField(
        null=True,
        blank=True,
        help_text='Confidence threshold active at scan time (e.g. 0.75).'
    )
    is_confident = models.BooleanField(
        null=True,
        blank=True,
        db_index=True,
        help_text='True = scan was CONFIDENT (no fallback). False = UNCERTAIN (fallback triggered).'
    )
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'pari_prediction'
        indexes = [
            models.Index(fields=['predicted_class']),
            models.Index(fields=['confidence']),
            models.Index(fields=['risk_score']),
            models.Index(fields=['is_confident'], name='idx_pred_is_confident'),
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
    """Junction table for many-to-many relationship between Scan and ThreatIndicator with explainability provenance"""
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='threat_indicators')
    indicator = models.ForeignKey(ThreatIndicator, on_delete=models.CASCADE)
    source_component = models.CharField(
        max_length=100,
        blank=True,
        default='',
        db_index=True,
        help_text='Subsystem/detector that produced this indicator (e.g. PARI, WebpageAnalyzer, NetworkAnalyzer, ThreatFox)'
    )
    reason = models.CharField(
        max_length=500,
        blank=True,
        default='',
        help_text='Structured explanation or trigger reason for recording this indicator'
    )
    severity = models.CharField(
        max_length=10,
        choices=ThreatIndicator.SEVERITY_CHOICES,
        null=True,
        blank=True,
        help_text='Instance severity override if different from indicator definition'
    )
    detected_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'pari_scan_indicator'
        unique_together = ('scan', 'indicator')
        indexes = [
            models.Index(fields=['scan']),
            models.Index(fields=['indicator']),
            models.Index(fields=['source_component'], name='idx_si_source'),
        ]
    
    def __str__(self):
        return f"Scan {self.scan.id} - {self.indicator.indicator_type} ({self.source_component or 'Unknown'})"



class ScanFeatures(models.Model):
    """
    Stores the exact 10 PARI RandomForest input features for each scan.

    These are the same feature values extracted by MLPredictionService.extract_pari_features()
    and passed to the RandomForest classifier. One row per scan; historical values are preserved
    permanently and are never overwritten.

    Old scans without a ScanFeatures row remain fully valid — the absence is acceptable.
    """

    scan = models.OneToOneField(
        Scan,
        on_delete=models.CASCADE,
        related_name='pari_features',
        help_text='The scan whose RandomForest features are recorded here.'
    )

    # Numeric feature columns — match the exact Python int values passed to the RF pipeline.
    url_len = models.IntegerField(
        help_text='Total character length of the URL string.'
    )
    letters_count = models.IntegerField(
        help_text='Count of ASCII letter characters in the URL.'
    )
    digits_count = models.IntegerField(
        help_text='Count of digit characters in the URL.'
    )
    special_chars_count = models.IntegerField(
        help_text='Count of non-alphanumeric/non-period characters in the URL.'
    )

    # 0/1 boolean-encoded features (stored as SmallIntegerField for SQL-native querying).
    shortened = models.SmallIntegerField(
        help_text='1 if URL uses a known shortening service, else 0.'
    )
    abnormal_url = models.SmallIntegerField(
        help_text='1 if URL exhibits abnormal structure (existing PARI logic), else 0.'
    )
    secure_http = models.SmallIntegerField(
        help_text='1 if URL scheme is HTTPS, else 0.'
    )
    have_ip = models.SmallIntegerField(
        help_text='1 if URL host is an IP address rather than a domain name, else 0.'
    )

    # Hash-encoded categorical features — BigIntegerField because hash values can exceed int32.
    url_region = models.BigIntegerField(
        help_text='Hash-encoded country/region of the primary domain TLD.'
    )
    root_domain = models.BigIntegerField(
        help_text='Hash-encoded root domain string.'
    )

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'pari_scan_features'
        indexes = [
            models.Index(fields=['have_ip'], name='idx_sf_have_ip'),
            models.Index(fields=['secure_http'], name='idx_sf_secure_http'),
            models.Index(fields=['shortened'], name='idx_sf_shortened'),
            models.Index(fields=['have_ip', 'secure_http'], name='idx_sf_have_ip_secure_http'),
        ]

    def __str__(self):
        return (
            f"ScanFeatures(scan={self.scan_id}, "
            f"have_ip={self.have_ip}, secure_http={self.secure_http}, "
            f"url_len={self.url_len})"
        )


class ScanFallbackResult(models.Model):
    """
    Stores the DeepAnalysis / Nikhil fallback result for scans that were
    UNCERTAIN after the initial RandomForest prediction.

    This record is written once the Nikhil pipeline completes and must NEVER
    overwrite or pollute the initial pari_prediction (RandomForest) row.

    Relationship:
        pari_scan  1 ──── 1  pari_scan_fallback   (one fallback result per scan)

    Old scans without a fallback row remain valid — the absence means the scan
    was either CONFIDENT (no fallback triggered) or predates Phase 3.
    """

    RISK_LEVEL_CHOICES = [
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]

    CLASSIFICATION_CHOICES = [
        ('Benign', 'Benign'),
        ('Phishing', 'Phishing'),
        ('Malware', 'Malware'),
        ('Defacement', 'Defacement'),
        ('Unknown', 'Unknown'),
    ]

    scan = models.OneToOneField(
        Scan,
        on_delete=models.CASCADE,
        related_name='fallback_result',
        help_text='The scan for which Nikhil fallback/deep analysis was performed.'
    )
    service_name = models.CharField(
        max_length=50,
        default='DeepAnalysis',
        help_text='Name of the fallback service (e.g. DeepAnalysis, Nikhil).'
    )
    classification = models.CharField(
        max_length=20,
        choices=CLASSIFICATION_CHOICES,
        db_index=True,
        help_text='Final fallback classification result.'
    )
    risk_score = models.FloatField(
        help_text='Risk score 0.0–1.0 from the fallback pipeline.'
    )
    risk_level = models.CharField(
        max_length=20,
        choices=RISK_LEVEL_CHOICES,
        null=True,
        blank=True,
        db_index=True,
        help_text='Categorical risk level returned by the fallback pipeline.'
    )
    evidence_summary = models.CharField(
        max_length=500,
        blank=True,
        default='',
        help_text='Bounded human-readable fallback evidence summary (max 500 chars).'
    )
    mongo_document_reference = models.CharField(
        max_length=100,
        null=True,
        blank=True,
        help_text='MongoDB document ID or reference string for the deep analysis case.'
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'pari_scan_fallback'
        indexes = [
            models.Index(fields=['classification'], name='idx_sfb_classification'),
            models.Index(fields=['risk_level'], name='idx_sfb_risk_level'),
            models.Index(fields=['risk_score'], name='idx_sfb_risk_score'),
        ]

    def __str__(self):
        return (
            f"FallbackResult(scan={self.scan_id}, "
            f"service={self.service_name}, "
            f"classification={self.classification}, "
            f"risk={self.risk_score:.2f})"
        )


class ScanEvidenceSummary(models.Model):
    """
    Stores a compact, structured evidence summary per evidence family for a scan.
    One row per evidence family per scan.

    Evidence families supported:
        WEBPAGE
        NETWORK
        VISUAL
        THREAT_INTELLIGENCE
        PROMPT_INJECTION
        SQL_HISTORY
        TRUSTED_DOMAIN

    (AI evidence is handled separately in Phase 5).
    """

    EVIDENCE_FAMILY_CHOICES = [
        ('WEBPAGE', 'Webpage'),
        ('NETWORK', 'Network'),
        ('VISUAL', 'Visual'),
        ('THREAT_INTELLIGENCE', 'Threat Intelligence'),
        ('PROMPT_INJECTION', 'Prompt Injection'),
        ('SQL_HISTORY', 'SQL History'),
        ('TRUSTED_DOMAIN', 'Trusted Domain'),
    ]

    STATUS_CHOICES = [
        ('SUCCESS', 'Success'),
        ('UNAVAILABLE', 'Unavailable'),
        ('ERROR', 'Error'),
        ('SKIPPED', 'Skipped'),
        ('TIMEOUT', 'Timeout'),
        ('FAILED', 'Failed'),
        ('NO_MATCH', 'No Match'),
        ('PENDING', 'Pending'),
        ('NOT_RUN', 'Not Run'),
    ]

    SEVERITY_CHOICES = [
        ('INFO', 'Info'),
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]

    scan = models.ForeignKey(
        Scan,
        on_delete=models.CASCADE,
        related_name='evidence_summaries',
        help_text='The scan this evidence summary belongs to.'
    )
    evidence_family = models.CharField(
        max_length=50,
        choices=EVIDENCE_FAMILY_CHOICES,
        db_index=True,
        help_text='The evidence category / family (e.g. WEBPAGE, THREAT_INTELLIGENCE).'
    )
    status = models.CharField(
        max_length=30,
        choices=STATUS_CHOICES,
        default='PENDING',
        help_text='Execution status of this evidence family collector.'
    )
    detected = models.BooleanField(
        null=True,
        blank=True,
        db_index=True,
        help_text='True if indicators/threats were detected by this family. Null if not applicable.'
    )
    match_found = models.BooleanField(
        null=True,
        blank=True,
        db_index=True,
        help_text='True if intelligence match was found. Null if not applicable.'
    )
    source_count = models.IntegerField(
        null=True,
        blank=True,
        help_text='Number of external sources/feeds checked by this family. Null if not applicable.'
    )
    evidence_count = models.IntegerField(
        default=0,
        help_text='Count of discrete evidence items, indicators, or findings extracted.'
    )
    severity = models.CharField(
        max_length=20,
        choices=SEVERITY_CHOICES,
        null=True,
        blank=True,
        help_text='Assessed severity level of the detected evidence if applicable.'
    )
    summary = models.CharField(
        max_length=500,
        blank=True,
        default='',
        help_text='Compact, bounded human-readable evidence summary (max 500 chars).'
    )
    source_component = models.CharField(
        max_length=100,
        blank=True,
        default='',
        db_index=True,
        help_text='Primary subsystem or provider that gathered this evidence family (e.g. WebpageAnalyzer, ThreatIntelService).'
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'pari_evidence_summary'
        constraints = [
            models.UniqueConstraint(
                fields=['scan', 'evidence_family'],
                name='uq_scan_evidence_family'
            )
        ]
        indexes = [
            models.Index(fields=['evidence_family'], name='idx_ev_family'),
            models.Index(fields=['evidence_family', 'match_found'], name='idx_ev_family_match'),
            models.Index(fields=['evidence_family', 'detected'], name='idx_ev_family_detected'),
            models.Index(fields=['status'], name='idx_ev_status'),
            models.Index(fields=['source_component'], name='idx_ev_source_component'),
        ]

    def __str__(self):
        return (
            f"EvidenceSummary(scan={self.scan_id}, "
            f"family={self.evidence_family}, "
            f"status={self.status}, "
            f"detected={self.detected}, "
            f"match={self.match_found})"
        )


class ScanAIEvidence(models.Model):
    """
    Stores a safe, compact, structured summary of AI evidence for a scan.
    One row per scan.

    Relationship:
        pari_scan 1 ───── 1 pari_ai_evidence

    AI states supported:
        - NOT_RUN: Gatekeeper decided AI was not needed, or AI disabled/timed out.
        - COMPLETED / SUCCESS: AI provider returned a structured assessment.
        - UNAVAILABLE / FAILED / ERROR: AI was required and attempted, but failed or exhausted retries.

    AI is an evidence source only, NEVER the final authority.
    Full detailed case files, logs, and prompt payloads remain in MongoDB deep_analysis_cases.
    """

    STATUS_CHOICES = [
        ('NOT_RUN', 'Not Run'),
        ('SUCCESS', 'Success'),
        ('COMPLETED', 'Completed'),
        ('UNAVAILABLE', 'Unavailable'),
        ('FAILED', 'Failed'),
        ('ERROR', 'Error'),
        ('TIMEOUT', 'Timeout'),
        ('RATE_LIMITED', 'Rate Limited'),
        ('QUOTA_EXCEEDED', 'Quota Exceeded'),
    ]

    ASSESSMENT_CHOICES = [
        ('LIKELY_BENIGN', 'Likely Benign'),
        ('LIKELY_PHISHING', 'Likely Phishing'),
        ('LIKELY_MALWARE', 'Likely Malware'),
        ('LIKELY_DEFACEMENT', 'Likely Defacement'),
        ('CONFLICTING', 'Conflicting'),
        ('INCONCLUSIVE', 'Inconclusive'),
        ('Benign', 'Benign'),
        ('Phishing', 'Phishing'),
        ('Malware', 'Malware'),
        ('Defacement', 'Defacement'),
        ('Suspicious', 'Suspicious'),
    ]

    scan = models.OneToOneField(
        Scan,
        on_delete=models.CASCADE,
        related_name='ai_evidence',
        help_text='The scan whose AI evidence is summarized here.'
    )
    provider = models.CharField(
        max_length=50,
        null=True,
        blank=True,
        db_index=True,
        help_text='AI provider name (e.g. gemini, openrouter). Null if not run.'
    )
    model = models.CharField(
        max_length=100,
        null=True,
        blank=True,
        db_index=True,
        help_text='Model identifier used (e.g. gemini-2.5-flash). Null if not run.'
    )
    status = models.CharField(
        max_length=30,
        choices=STATUS_CHOICES,
        default='NOT_RUN',
        db_index=True,
        help_text='Execution status of the AI module (NOT_RUN, SUCCESS, UNAVAILABLE, etc.).'
    )
    assessment = models.CharField(
        max_length=50,
        choices=ASSESSMENT_CHOICES,
        null=True,
        blank=True,
        db_index=True,
        help_text='Structured AI assessment if returned (e.g. LIKELY_PHISHING). Null if not available.'
    )
    confidence = models.FloatField(
        null=True,
        blank=True,
        help_text='AI confidence score (0.0 to 1.0) only if returned by the AI provider. Null otherwise.'
    )
    risk_score = models.FloatField(
        null=True,
        blank=True,
        help_text='AI risk score (0.0 to 1.0) only if returned by the AI provider. Null otherwise.'
    )
    ai_required = models.BooleanField(
        default=False,
        db_index=True,
        help_text='True if the AI gatekeeper evaluated that AI analysis was required.'
    )
    ai_called = models.BooleanField(
        default=False,
        db_index=True,
        help_text='True if an external AI provider call was actually dispatched.'
    )
    reasoning_summary = models.CharField(
        max_length=500,
        blank=True,
        default='',
        help_text='Bounded, safe human-readable reasoning summary or gatekeeper decision reason.'
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'pari_ai_evidence'
        indexes = [
            models.Index(fields=['status'], name='idx_ai_status'),
            models.Index(fields=['provider'], name='idx_ai_provider'),
            models.Index(fields=['model'], name='idx_ai_model'),
            models.Index(fields=['assessment'], name='idx_ai_assessment'),
            models.Index(fields=['ai_required'], name='idx_ai_required'),
            models.Index(fields=['ai_called'], name='idx_ai_called'),
        ]

    def __str__(self):
        return (
            f"AIEvidence(scan={self.scan_id}, "
            f"status={self.status}, "
            f"provider={self.provider}, "
            f"assessment={self.assessment})"
        )


class ScanFinalDecision(models.Model):
    """
    Stores the official, authoritative final classification and decision record
    for a scan.

    Distinct from:
    1. Initial ML prediction (pari_prediction)
    2. Fallback execution result (pari_scan_fallback)
    3. Family-level evidence summaries (pari_evidence_summary)
    4. Individual threat indicators (pari_scan_indicator)
    5. AI evidence summary (pari_ai_evidence)

    Relationship:
        pari_scan  1 ──── 1  pari_final_decision   (one final decision per scan)

    Old scans without a final decision record remain fully readable and valid.
    """

    CLASSIFICATION_CHOICES = [
        ('Benign', 'Benign'),
        ('Phishing', 'Phishing'),
        ('Malware', 'Malware'),
        ('Defacement', 'Defacement'),
        ('Unknown', 'Unknown'),
        ('Needs Review', 'Needs Review'),
    ]

    RISK_LEVEL_CHOICES = [
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]

    DECISION_STATUS_CHOICES = [
        ('FINAL', 'Final - Deterministic Corroboration'),
        ('CONFIDENT_ML', 'Confident - Initial Machine Learning'),
        ('NEEDS_REVIEW', 'Needs Review - Insufficient / Conflicting Evidence'),
        ('OVERRIDDEN', 'Overridden - Analyst Review'),
    ]

    scan = models.OneToOneField(
        Scan,
        on_delete=models.CASCADE,
        related_name='final_decision',
        help_text='The scan whose official final decision is recorded here.'
    )
    final_classification = models.CharField(
        max_length=20,
        choices=CLASSIFICATION_CHOICES,
        db_index=True,
        help_text='Official final classification outcome.'
    )
    risk_score = models.FloatField(
        help_text='Official final risk score (0.0 to 1.0).'
    )
    risk_level = models.CharField(
        max_length=20,
        choices=RISK_LEVEL_CHOICES,
        db_index=True,
        help_text='Categorical risk level (LOW, MEDIUM, HIGH, CRITICAL).'
    )
    decision_status = models.CharField(
        max_length=30,
        choices=DECISION_STATUS_CHOICES,
        default='FINAL',
        db_index=True,
        help_text='Decision status (FINAL, CONFIDENT_ML, NEEDS_REVIEW, etc.).'
    )
    decision_method = models.CharField(
        max_length=50,
        default='DETERMINISTIC_CORROBORATION',
        db_index=True,
        help_text='Method or subsystem that generated the final decision.'
    )
    corroboration_strength = models.CharField(
        max_length=30,
        null=True,
        blank=True,
        help_text='Strength of multi-family corroboration (e.g. STRONG, MODERATE, WEAK, NONE).'
    )
    evidence_family_count = models.IntegerField(
        default=0,
        help_text='Count of distinct independent evidence families contributing to the decision.'
    )
    conflict_detected = models.BooleanField(
        default=False,
        db_index=True,
        help_text='True if conflicting signals were observed between evidence families.'
    )
    decision_summary = models.CharField(
        max_length=500,
        blank=True,
        default='',
        help_text='Bounded human-readable decision summary.'
    )
    decision_timestamp = models.DateTimeField(
        auto_now_add=True,
        db_index=True,
        help_text='Timestamp when the final decision was established.'
    )

    class Meta:
        db_table = 'pari_final_decision'
        indexes = [
            models.Index(fields=['final_classification'], name='idx_fd_classification'),
            models.Index(fields=['risk_level'], name='idx_fd_risk_level'),
            models.Index(fields=['risk_score'], name='idx_fd_risk_score'),
            models.Index(fields=['decision_method'], name='idx_fd_method'),
            models.Index(fields=['decision_status'], name='idx_fd_status'),
            models.Index(fields=['decision_timestamp'], name='idx_fd_timestamp'),
            models.Index(fields=['final_classification', 'risk_level'], name='idx_fd_class_risk'),
        ]

    def __str__(self):
        return f"FinalDecision(scan={self.scan_id}, class={self.final_classification}, risk={self.risk_score:.2f})"


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