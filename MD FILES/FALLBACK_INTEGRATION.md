# FALLBACK_INTEGRATION — Contract Definition

## Overview
This document defines the interface between the PARI ML system and the Nikhil deep-analysis fallback system.

## 1. Trigger Condition
The fallback system is triggered when a scan is marked as `UNCERTAIN`.
- **Condition**: Confidence < 0.75 (PARI_CONFIDENCE_THRESHOLD)
- **Status**: `UNCERTAIN`

## 2. Handoff Contract (PARI → NIKHIL)

**Format**: JSON Object
**Transmission**: Internal Service Call

| Field | Type | Description |
|-------|------|-------------|
| `scan_id` | integer | Unique identifier for the scan record |
| `url` | string | The URL being analyzed |
| `initial_predicted_class` | string | The class predicted by the ML model (Benign, Phishing, etc.) |
| `initial_confidence` | float | The confidence score from the ML model (0.0 - 1.0) |
| `scan_status` | string | Always "UNCERTAIN" for fallback triggers |
| `risk_score` | float | Initial risk score (usually 1.0 - confidence) |
| `model_name` | string | Name of the initial model (e.g., "RandomForest") |
| `fallback_endpoint` | string | The endpoint to return results: `/api/fallback/result/` |
| `timestamp` | string | ISO-8601 timestamp of the initial scan |

## 3. Return Contract (NIKHIL → PARI)

**Format**: JSON Object
**Transmission**: POST to `/api/fallback/result/`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `scan_id` | integer | Yes | Original scan identifier |
| `analysis_status` | string | Yes | Status of deep analysis (e.g., "COMPLETED", "FAILED") |
| `final_classification` | string | Yes | One of: Benign, Phishing, Malware, Defacement, Unknown |
| `risk_level` | string | Yes | One of: LOW, MEDIUM, HIGH, CRITICAL |
| `risk_score` | float | Yes | Final calculated risk (0.0 - 1.0) |
| `evidence_summary` | string | No | Human-readable summary of analysis findings |
| `threat_indicators` | list[str]| No | List of indicators in "TYPE:VALUE" format |
| `mongo_document_reference`| string | No | Link to raw evidence in MongoDB |
| `original_prediction` | string | No | Preservation of initial ML result |
| `original_confidence` | float | No | Preservation of initial ML confidence |

## 4. Final Classifications Mapping
The fallback system maps its findings to one of the following canonical classes:
1. **Benign**: No malicious indicators found.
2. **Phishing**: Evidence of social engineering or credential theft.
3. **Malware**: Evidence of harmful software or exploits.
4. **Defacement**: Evidence of website hijacking or content alteration.
5. **Unknown**: Insufficient evidence to confidently classify.

## 5. Security Rules
1. **Timeouts**: Webpage and Network fetches MUST time out within 10 seconds.
2. **Untrusted Content**: HTML content is treated as DATA. No JavaScript execution.
3. **Graceful Failure**: If a module (e.g., AI Analysis) fails, the fallback must proceed with remaining evidence.
