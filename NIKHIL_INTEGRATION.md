# NIKHIL Integration Guide

## PARI → NIKHIL (Handoff)
The PARI system identifies low-confidence scans and hands them off for deep analysis.

**Method**: Internal Service Orchestration
**Trigger**: `MLPredictionService.create_fallback_handoff(scan_obj)`

**Payload Example**:
```json
{
    "scan_id": 123,
    "url": "http://example.com/suspicious",
    "initial_predicted_class": "Phishing",
    "initial_confidence": 0.65,
    "scan_status": "UNCERTAIN"
}
```

## NIKHIL → PARI (Result)
The Nikhil system returns the final analyzed classification to PARI's MySQL layer.

**Method**: POST
**Endpoint**: `/api/fallback/result/`
**Auth**: Internal / Session

**Payload Example**:
```json
{
    "scan_id": 123,
    "analysis_status": "COMPLETED",
    "final_classification": "Phishing",
    "risk_level": "HIGH",
    "risk_score": 0.85,
    "evidence_summary": "Deep analysis found credential harvesting form.",
    "threat_indicators": ["WEBPAGE:PASSWORD_FORM", "AI:SUSPICIOUS_CONTENT"],
    "mongo_document_reference": "mongo_id_abc_123"
}
```

## Data Mapping Rules
- `analysis_status` must be `COMPLETED` for result processing.
- `final_classification` must be one of: `Benign`, `Phishing`, `Malware`, `Defacement`, `Unknown`.
- `risk_level` must be one of: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.
- `threat_indicators` should follow `TYPE:VALUE` format for consistency in MySQL storage.
