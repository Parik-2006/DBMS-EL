"""
Historical Intelligence module for Nikhil pipeline.
Re-exports HistoricalIntelligenceService from User.services.historical_intelligence_service.
"""

from User.services.historical_intelligence_service import HistoricalIntelligenceService, DomainIntelligenceService

__all__ = ["HistoricalIntelligenceService", "DomainIntelligenceService"]
