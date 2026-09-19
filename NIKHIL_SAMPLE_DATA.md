# NIKHIL Sample Data

## 1. Uncertain Scan (PARI Handoff)
```json
{
    "scan_id": 6,
    "url": "https://test-example.com/page1",
    "initial_predicted_class": "Phishing",
    "initial_confidence": 0.62,
    "scan_status": "UNCERTAIN",
    "risk_score": 0.62,
    "model_name": "RandomForest",
    "fallback_endpoint": "/api/fallback/result/",
    "timestamp": "2026-09-19T10:15:30.123456"
}
```

## 2. Webpage Evidence (Nikhil Analysis)
```json
{
    "status": "SUCCESS",
    "url": "https://test-example.com/page1",
    "title": "Login Page",
    "text": "Please enter your username and password to login...",
    "html_summary": "<html>...</html>",
    "metadata": {"description": "Secure Login"},
    "forms": [{"action": "/login", "method": "post", "inputs": ["username", "password"]}],
    "suspicious_elements": ["PASSWORD_FORM"],
    "javascript_indicators": [],
    "redirects": [],
    "content_type": "text/html",
    "timestamp": 1726740930.0
}
```

## 3. Network Evidence
```json
{
    "status": "SUCCESS",
    "domain": "test-example.com",
    "ip": "93.184.216.34",
    "dns": {"resolved_ip": "93.184.216.34"},
    "redirects": [],
    "ssl": {"verified": true},
    "timestamp": 1726740930.5
}
```

## 4. AI Analysis Result
```json
{
    "status": "MOCK",
    "findings": [],
    "suspicious_patterns": [],
    "prompt_injection_detected": false,
    "explanation": "Mock analysis performed.",
    "timestamp": 1726740931.0
}
```

## 5. MongoDB Document
```json
{
    "_id": "66eba792e8a1f8b4d5e2a1b1",
    "scan_id": 6,
    "url": "https://test-example.com/page1",
    "analysis_status": "COMPLETED",
    "webpage": { ... },
    "network": { ... },
    "ai_analysis": { ... },
    "additional_evidence": { ... },
    "timestamps": {
        "started_at": 1726740930.0,
        "completed_at": 1726740931.5
    }
}
```

## 6. Final Classification Result (Returned to PARI)
```json
{
    "scan_id": 6,
    "analysis_status": "COMPLETED",
    "final_classification": "Phishing",
    "risk_level": "HIGH",
    "risk_score": 0.8,
    "evidence_summary": "Mock analysis performed. Found suspicious form elements.",
    "threat_indicators": ["WEBPAGE:PASSWORD_FORM"],
    "mongo_document_reference": "66eba792e8a1f8b4d5e2a1b1",
    "original_prediction": "Phishing",
    "original_confidence": 0.62
}
```

## 7. Analyst Review
```json
{
    "scan_id": 6,
    "final_label": "Phishing",
    "review_notes": "Confirmed phishing page targeting credentials.",
    "validation_status": "VALIDATED"
}
```
