from django.db import models
from django.contrib.auth.models import User
from User.models import Scan

class AnalystReview(models.Model):
    """Analyst review record for Unknown/Needs Review cases"""
    
    VALIDATION_CHOICES = [
        ('BENIGN', 'Benign'),
        ('PHISHING', 'Phishing'),
        ('MALWARE', 'Malware'),
        ('DEFACEMENT', 'Defacement'),
        ('STILL_UNKNOWN', 'Still Unknown'),
    ]
    
    VALIDATED_CHOICES = [
        ('VALIDATED', 'Validated for future training'),
        ('NOT_VALIDATED', 'Not validated'),
    ]
    
    scan = models.OneToOneField(Scan, on_delete=models.CASCADE, related_name='analyst_review')
    reviewer = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    reviewed_at = models.DateTimeField(auto_now_add=True)
    final_label = models.CharField(max_length=20, choices=VALIDATION_CHOICES)
    review_notes = models.TextField(blank=True, null=True)
    validation_status = models.CharField(max_length=20, choices=VALIDATED_CHOICES, default='NOT_VALIDATED')
    
    class Meta:
        db_table = 'pari_analyst_review'
        
    def __str__(self):
        return f"Review for Scan {self.scan.id}: {self.final_label}"
