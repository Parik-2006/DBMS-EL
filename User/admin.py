from django.contrib import admin
from .models import (
    MaliciousBot, Domain, URL, IP, Scan, Prediction,
    ThreatIndicator, ScanIndicator
)

@admin.register(MaliciousBot)
class MaliciousBotAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'url', 'prediction_type', 'confidence', 'timestamp')
    list_filter = ('prediction_type', 'timestamp', 'user')
    search_fields = ('url', 'user__username')
    readonly_fields = ('timestamp',)
    ordering = ('-timestamp',)

@admin.register(Domain)
class DomainAdmin(admin.ModelAdmin):
    list_display = ('domain_name', 'tld', 'status', 'risk_score', 'last_scanned')
    list_filter = ('status', 'created_at')
    search_fields = ('domain_name', 'tld')
    readonly_fields = ('created_at', 'updated_at')
    ordering = ('-risk_score',)

@admin.register(URL)
class URLAdmin(admin.ModelAdmin):
    list_display = ('url', 'domain', 'source', 'baseline_label', 'created_at')
    list_filter = ('source', 'baseline_label', 'created_at')
    search_fields = ('url', 'domain__domain_name')
    readonly_fields = ('created_at',)
    ordering = ('-created_at',)

@admin.register(IP)
class IPAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'status', 'country', 'risk_score', 'created_at')
    list_filter = ('status', 'country', 'created_at')
    search_fields = ('ip_address', 'country')
    readonly_fields = ('created_at', 'updated_at')
    ordering = ('-risk_score',)

@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'url', 'status', 'initial_model', 'created_at')
    list_filter = ('status', 'initial_model', 'created_at')
    search_fields = ('url__url', 'user__username')
    readonly_fields = ('created_at', 'updated_at')
    ordering = ('-created_at',)

@admin.register(Prediction)
class PredictionAdmin(admin.ModelAdmin):
    list_display = ('id', 'scan', 'model_name', 'predicted_class', 'confidence', 'risk_score')
    list_filter = ('predicted_class', 'model_name', 'created_at')
    search_fields = ('scan__url__url',)
    readonly_fields = ('created_at', 'updated_at')
    ordering = ('-created_at',)

@admin.register(ThreatIndicator)
class ThreatIndicatorAdmin(admin.ModelAdmin):
    list_display = ('indicator_type', 'indicator_value', 'severity', 'created_at')
    list_filter = ('indicator_type', 'severity', 'created_at')
    search_fields = ('indicator_value',)
    readonly_fields = ('created_at',)
    ordering = ('-created_at',)

@admin.register(ScanIndicator)
class ScanIndicatorAdmin(admin.ModelAdmin):
    list_display = ('scan', 'indicator', 'detected_at')
    list_filter = ('detected_at', 'indicator__severity')
    search_fields = ('scan__url__url', 'indicator__indicator_value')
    readonly_fields = ('detected_at',)
    ordering = ('-detected_at',)