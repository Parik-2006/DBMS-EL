import numpy as np
from datetime import datetime
from urllib.parse import urlparse
from User.models import Scan, Prediction, URL, Domain, ThreatIndicator, ScanIndicator
from User.services import get_confidence_threshold
import json

class MLPredictionService:
    """Service for making predictions with confidence routing"""
    
    CLASS_MAPPING = {
        0: 'Benign',
        1: 'Defacement',
        2: 'Phishing',
        3: 'Malware'
    }
    
    @staticmethod
    def create_scan_record(url_obj, user=None):
        """Create a new scan record"""
        scan = Scan.objects.create(
            user=user,
            url=url_obj,
            status='UNCERTAIN',
            initial_model='RandomForest'
        )
        return scan
    
    @staticmethod
    def make_prediction(pipeline, url, scan_obj):
        """
        Make prediction using pipeline and store result with confidence routing
        
        Returns:
            {
                'scan_id': int,
                'url': str,
                'predicted_class': str,
                'confidence': float,
                'risk_score': float,
                'scan_status': str,
                'model_name': str,
                'probabilities': dict,
                'is_confident': bool,
                'fallback_needed': bool
            }
        """
        try:
            from User.views import (
                get_url_length, count_letters, count_digits,
                count_special_chars, has_shortening_service,
                abnormal_url, secure_http, have_ip_address,
                extract_root_domain, hash_encode, get_url_region
            )
            
            url_len = get_url_length(str(url))
            letters_count = count_letters(url)
            digits_count = count_digits(url)
            special_chars_count = count_special_chars(url)
            shortened = has_shortening_service(url)
            abnormal = abnormal_url(url)
            secure = secure_http(url)
            have_ip = have_ip_address(url)
            pri_domain = extract_root_domain(url)
            url_region = hash_encode(get_url_region(str(pri_domain)))
            root_domain = hash_encode(str(pri_domain))
            
            features = np.array([[url_len, letters_count, digits_count, special_chars_count,
                                shortened, abnormal, secure, have_ip, url_region, root_domain]])
            
            prediction_class = pipeline.predict(features)[0]
            probabilities = pipeline.predict_proba(features)[0]
            
            confidence = max(probabilities)
            predicted_class_name = MLPredictionService.CLASS_MAPPING.get(prediction_class, 'Unknown')
            risk_score = 1.0 - confidence if predicted_class_name == 'Benign' else confidence
            
            threshold = get_confidence_threshold()
            is_confident = confidence >= threshold
            
            scan_status = 'CONFIDENT' if is_confident else 'UNCERTAIN'
            scan_obj.status = scan_status
            scan_obj.save()
            
            prediction = Prediction.objects.create(
                scan=scan_obj,
                model_name='RandomForest',
                predicted_class=predicted_class_name,
                confidence=confidence,
                risk_score=risk_score,
                probabilities={
                    'Benign': float(probabilities[0]),
                    'Defacement': float(probabilities[1]),
                    'Phishing': float(probabilities[2]),
                    'Malware': float(probabilities[3])
                }
            )
            
            return {
                'scan_id': scan_obj.id,
                'url': url,
                'predicted_class': predicted_class_name,
                'confidence': float(confidence),
                'risk_score': float(risk_score),
                'scan_status': scan_status,
                'model_name': 'RandomForest',
                'probabilities': prediction.probabilities,
                'is_confident': is_confident,
                'fallback_needed': not is_confident,
                'prediction_id': prediction.id
            }
            
        except Exception as e:
            scan_obj.status = 'ERROR'
            scan_obj.save()
            raise
    
    @staticmethod
    def create_fallback_handoff(scan_obj):
        """
        Create handoff contract for uncertain predictions
        
        Returns:
            {
                'scan_id': int,
                'url': str,
                'initial_predicted_class': str,
                'initial_confidence': float,
                'scan_status': str,
                'risk_score': float,
                'model_name': str,
                'fallback_endpoint': str,
                'timestamp': str
            }
        """
        if not hasattr(scan_obj, 'prediction') or not scan_obj.prediction:
            return None
        
        prediction = scan_obj.prediction
        
        return {
            'scan_id': scan_obj.id,
            'url': scan_obj.url.url,
            'initial_predicted_class': prediction.predicted_class,
            'initial_confidence': prediction.confidence,
            'scan_status': scan_obj.status,
            'risk_score': prediction.risk_score,
            'model_name': scan_obj.initial_model,
            'fallback_endpoint': '/api/fallback/result/',
            'timestamp': scan_obj.created_at.isoformat() if scan_obj.created_at else None
        }
