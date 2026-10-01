import numpy as np
from datetime import datetime
from urllib.parse import urlparse
from User.models import Scan, Prediction, URL, Domain, ThreatIndicator, ScanIndicator, ScanFeatures
from User.services import get_confidence_threshold
import json
import logging

logger = logging.getLogger(__name__)


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
    def extract_pari_features(url):
        """
        Extract the exact 10 PARI features using existing extraction logic.
        Source of truth: User.views feature extractors.
        Returns dict with exact 10 features:
            url_len (int)
            letters_count (int)
            digits_count (int)
            special_chars_count (int)
            shortened (int)
            abnormal_url (int)
            secure_http (int)
            have_ip (int)
            url_region (int)
            root_domain (int)
        """
        from User.views import (
            get_url_length, count_letters, count_digits,
            count_special_chars, has_shortening_service,
            abnormal_url, secure_http, have_ip_address,
            extract_root_domain, hash_encode, get_url_region
        )

        url_str = str(url)
        url_len = int(get_url_length(url_str))
        letters_count = int(count_letters(url_str))
        digits_count = int(count_digits(url_str))
        special_chars_count = int(count_special_chars(url_str))
        shortened = int(has_shortening_service(url_str))
        abnormal = int(abnormal_url(url_str))
        secure = int(secure_http(url_str))
        have_ip = int(have_ip_address(url_str))
        pri_domain = extract_root_domain(url_str)
        url_region = int(hash_encode(get_url_region(str(pri_domain))))
        root_domain = int(hash_encode(str(pri_domain)))

        return {
            'url_len': url_len,
            'letters_count': letters_count,
            'digits_count': digits_count,
            'special_chars_count': special_chars_count,
            'shortened': shortened,
            'abnormal_url': abnormal,
            'secure_http': secure,
            'have_ip': have_ip,
            'url_region': url_region,
            'root_domain': root_domain
        }

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
                'fallback_needed': bool,
                'pari_features': dict
            }
        """
        try:
            pari_features = MLPredictionService.extract_pari_features(url)

            features = np.array([[
                pari_features['url_len'],
                pari_features['letters_count'],
                pari_features['digits_count'],
                pari_features['special_chars_count'],
                pari_features['shortened'],
                pari_features['abnormal_url'],
                pari_features['secure_http'],
                pari_features['have_ip'],
                pari_features['url_region'],
                pari_features['root_domain']
            ]])

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
                },
                # --- PHASE 3: initial-ML snapshot fields ---
                threshold_used=threshold,
                is_confident=is_confident,
            )

            # --- PHASE 2: Persist PARI 10 features in MySQL ---
            # Uses the exact same pari_features dict already passed to RandomForest.
            # get_or_create ensures idempotency; the scan field is OneToOne so
            # a second call for the same scan simply returns the existing row.
            try:
                ScanFeatures.objects.get_or_create(
                    scan=scan_obj,
                    defaults={
                        'url_len':              pari_features['url_len'],
                        'letters_count':        pari_features['letters_count'],
                        'digits_count':         pari_features['digits_count'],
                        'special_chars_count':  pari_features['special_chars_count'],
                        'shortened':            pari_features['shortened'],
                        'abnormal_url':         pari_features['abnormal_url'],
                        'secure_http':          pari_features['secure_http'],
                        'have_ip':              pari_features['have_ip'],
                        'url_region':           pari_features['url_region'],
                        'root_domain':          pari_features['root_domain'],
                    }
                )
            except Exception as feat_err:
                # Never allow a MySQL feature-write failure to crash the scan pipeline.
                logger.error(
                    "Failed to persist ScanFeatures for scan %s: %s",
                    scan_obj.id, feat_err
                )
            # --- END PHASE 2 ---

            # --- PHASE 10: Persist confident final decision if RF is confident ---
            if is_confident:
                try:
                    from User.services.fallback_service import FallbackIntegrationService
                    FallbackIntegrationService.persist_confident_final_decision(
                        scan=scan_obj,
                        predicted_class=predicted_class_name,
                        confidence=confidence,
                        risk_score=risk_score
                    )
                except Exception as fd_err:
                    logger.error(
                        "Failed to persist confident ScanFinalDecision for scan %s: %s",
                        scan_obj.id, fd_err
                    )
            # --- END PHASE 10 ---


            scan_obj._pari_features = pari_features
            prediction._pari_features = pari_features

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
                'prediction_id': prediction.id,
                'pari_features': pari_features
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
                'timestamp': str,
                'pari_features': dict
            }
        """
        if not hasattr(scan_obj, 'prediction') or not scan_obj.prediction:
            return None

        prediction = scan_obj.prediction

        handoff = {
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

        if hasattr(scan_obj, '_pari_features'):
            handoff['pari_features'] = scan_obj._pari_features
        elif hasattr(prediction, '_pari_features'):
            handoff['pari_features'] = prediction._pari_features
        elif scan_obj.url and hasattr(scan_obj.url, 'url'):
            handoff['pari_features'] = MLPredictionService.extract_pari_features(scan_obj.url.url)

        return handoff
