from django.db import models
from django.contrib.auth.models import User

# Create your models here.
class MaliciousBot(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
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