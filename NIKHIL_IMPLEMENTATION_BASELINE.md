# NIKHIL — Implementation Baseline

## Current Project Architecture
- **Framework**: Django 5.2.13
- **Primary Database**: SQLite (db.sqlite3)
- **ML Components**:
    - **Models**: Random Forest (Primary), Logistic Regression (Fallback)
    - **Classes**: Benign, Phishing, Malware, Defacement
    - **Dataset**: 400-row labeled CSV (`static/dataset/Phishing.csv`)
- **Key Models**:
    - `MaliciousBot`: Original prediction records.
    - `Scan`: Represents a URL analysis session.
    - `Prediction`: Stores ML output and confidence.
    - `Domain`, `URL`, `IP`: Normalized relational data.
    - `ThreatIndicator`, `ScanIndicator`: Extracted security signals.

## Existing PARI Integration Point
- **Service**: `User/services/fallback_service.py:FallbackIntegrationService`
- **Endpoint**: `/api/fallback/result/` (implemented in `User/api.py:fallback_result`)
- **Routing**: `MLPredictionService.make_prediction` routes to `UNCERTAIN` if confidence < 0.75.

## Data Contracts

### Handoff to Nikhil (Pari → Nikhil)
Produced by `MLPredictionService.create_fallback_handoff`:
- `scan_id`: integer
- `url`: string
- `initial_predicted_class`: string
- `initial_confidence`: float
- `scan_status`: string ("UNCERTAIN")
- `risk_score`: float
- `model_name`: string
- `fallback_endpoint`: string (`/api/fallback/result/`)
- `timestamp`: ISO string

### Expected Output (Nikhil → Pari)
Validated by `FallbackIntegrationService.validate_fallback_result`:
- `scan_id`: integer
- `analysis_status`: string
- `final_classification`: string ('Benign', 'Phishing', 'Malware', 'Defacement', 'Unknown')
- `risk_level`: string ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
- `risk_score`: float (0.0 - 1.0)
- `evidence_summary`: string
- `threat_indicators`: list of strings (format: "TYPE:VALUE")
- `mongo_document_reference`: string (optional)

## Proposed Modifications
- **New Files**:
    - `User/services/nikhil/`: Package for deep analysis modules.
    - `User/services/nikhil/orchestration_service.py`: Central fallback logic.
    - `User/services/nikhil/webpage_analyzer.py`: HTML/Web analysis.
    - `User/services/nikhil/network_analyzer.py`: DNS/IP/SSL analysis.
    - `User/services/nikhil/ai_analyzer.py`: LLM/AI modules.
    - `User/services/nikhil/mongodb_repository.py`: MongoDB interface.
    - `User/services/nikhil/final_classifier.py`: Rule-based classification.
- **Modified Files**:
    - `User/models.py`: Add `AnalystReview` and `ValidatedCandidate` models.
    - `User/api.py`: Add endpoints for analyst review and investigation.
    - `User/urls.py`: Register new API endpoints.
    - `User/tests.py`: Add Nikhil-specific unit tests.

## Untouched Files
- `static/dataset/Phishing.csv`: Baseline dataset frozen.
- Existing ML logic in `User/views.py`: Preserved.
- Random Forest and Logistic Regression implementations: Preserved.
- PARI Relational Schema: Preserved (extended only).

## Safety & Performance
- URLs are untrusted. Modules will use `requests` with strict timeouts and redirect limits.
- No execution of untrusted JavaScript.
- LLM findings treated as data, not instructions.
