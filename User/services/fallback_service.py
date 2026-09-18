from django.db import transaction
from django.utils import timezone
from User.models import Scan, Prediction, ThreatIndicator, ScanIndicator
import json

class FallbackIntegrationService:
    """Service for receiving and processing fallback system results"""
    
    VALID_CLASSIFICATIONS = ['Benign', 'Phishing', 'Malware', 'Defacement', 'Unknown']
    VALID_RISK_LEVELS = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
    
    @staticmethod
    def validate_fallback_result(data):
        """
        Validate incoming fallback result against contract
        
        Expected format:
        {
            'scan_id': int,
            'analysis_status': str,
            'final_classification': str,
            'risk_level': str,
            'risk_score': float,
            'evidence_summary': str,
            'threat_indicators': [str],
            'mongo_document_reference': str (optional)
        }
        """
        errors = []
        
        if not isinstance(data, dict):
            errors.append("Result must be a dictionary")
            return False, errors
        
        required_fields = ['scan_id', 'analysis_status', 'final_classification', 'risk_level', 'risk_score']
        for field in required_fields:
            if field not in data:
                errors.append(f"Missing required field: {field}")
        
        if 'scan_id' in data:
            try:
                scan_id = int(data['scan_id'])
                if not Scan.objects.filter(id=scan_id).exists():
                    errors.append(f"Scan ID {scan_id} not found")
            except (ValueError, TypeError):
                errors.append("scan_id must be an integer")
        
        if 'final_classification' in data:
            if data['final_classification'] not in FallbackIntegrationService.VALID_CLASSIFICATIONS:
                errors.append(f"Invalid classification: {data['final_classification']}")
        
        if 'risk_level' in data:
            if data['risk_level'] not in FallbackIntegrationService.VALID_RISK_LEVELS:
                errors.append(f"Invalid risk_level: {data['risk_level']}")
        
        if 'risk_score' in data:
            try:
                risk_score = float(data['risk_score'])
                if not 0.0 <= risk_score <= 1.0:
                    errors.append("risk_score must be between 0.0 and 1.0")
            except (ValueError, TypeError):
                errors.append("risk_score must be a float")
        
        if 'threat_indicators' in data:
            if not isinstance(data['threat_indicators'], list):
                errors.append("threat_indicators must be a list")
        
        return len(errors) == 0, errors
    
    @staticmethod
    @transaction.atomic
    def process_fallback_result(result_data):
        """
        Process fallback system result and update scan/prediction records
        
        Returns:
            {
                'success': bool,
                'scan_id': int,
                'message': str,
                'errors': [str]
            }
        """
        errors = []
        
        valid, validation_errors = FallbackIntegrationService.validate_fallback_result(result_data)
        if not valid:
            return {
                'success': False,
                'scan_id': result_data.get('scan_id'),
                'message': 'Validation failed',
                'errors': validation_errors
            }
        
        try:
            scan_id = int(result_data['scan_id'])
            scan = Scan.objects.get(id=scan_id)
            
            final_classification = result_data['final_classification']
            risk_score = float(result_data['risk_score'])
            analysis_status = result_data['analysis_status']
            threat_indicators = result_data.get('threat_indicators', [])
            evidence_summary = result_data.get('evidence_summary', '')
            mongo_ref = result_data.get('mongo_document_reference')
            
            if scan.status not in ['UNCERTAIN', 'DEEP_ANALYSIS']:
                errors.append(f"Cannot update scan in status {scan.status}. Expected UNCERTAIN or DEEP_ANALYSIS.")
                return {
                    'success': False,
                    'scan_id': scan_id,
                    'message': 'Invalid scan state',
                    'errors': errors
                }
            
            if scan.prediction:
                scan.prediction.predicted_class = final_classification
                scan.prediction.risk_score = risk_score
                scan.prediction.model_name = 'DeepAnalysis'
                scan.prediction.save()
            else:
                prediction = Prediction.objects.create(
                    scan=scan,
                    model_name='DeepAnalysis',
                    predicted_class=final_classification,
                    confidence=1.0,
                    risk_score=risk_score,
                    probabilities={'final': True}
                )
            
            for indicator_str in threat_indicators:
                try:
                    indicator_type = indicator_str.split(':')[0].strip() if ':' in indicator_str else 'OTHER'
                    indicator_value = indicator_str.split(':', 1)[1].strip() if ':' in indicator_str else indicator_str
                    
                    threat_indicator, created = ThreatIndicator.objects.get_or_create(
                        indicator_type=indicator_type,
                        indicator_value=indicator_value,
                        defaults={'severity': 'MEDIUM'}
                    )
                    
                    scan_indicator, created = ScanIndicator.objects.get_or_create(
                        scan=scan,
                        indicator=threat_indicator
                    )
                except Exception as e:
                    errors.append(f"Error processing threat indicator {indicator_str}: {str(e)}")
            
            scan.status = 'COMPLETED'
            scan.fallback_model = 'DeepAnalysis'
            scan.completed_at = timezone.now()
            scan.save()
            
            return {
                'success': True,
                'scan_id': scan_id,
                'message': f'Scan {scan_id} completed. Final classification: {final_classification} (Risk: {risk_score:.2f})',
                'errors': errors if errors else None
            }
        
        except Scan.DoesNotExist:
            return {
                'success': False,
                'scan_id': result_data.get('scan_id'),
                'message': f"Scan {result_data.get('scan_id')} not found",
                'errors': ['Scan not found in database']
            }
        except Exception as e:
            return {
                'success': False,
                'scan_id': result_data.get('scan_id'),
                'message': f'Error processing result: {str(e)}',
                'errors': [str(e)]
            }
    
    @staticmethod
    def get_uncertain_scans(limit=10):
        """Get scans awaiting fallback analysis"""
        return Scan.objects.filter(
            status='UNCERTAIN'
        ).select_related('url', 'user', 'prediction').order_by('-created_at')[:limit]
    
    @staticmethod
    def get_scan_status(scan_id):
        """Get current status of a scan"""
        try:
            scan = Scan.objects.get(id=scan_id)
            prediction = scan.prediction if hasattr(scan, 'prediction') else None
            
            return {
                'scan_id': scan.id,
                'url': scan.url.url if scan.url else None,
                'status': scan.status,
                'created_at': scan.created_at.isoformat() if scan.created_at else None,
                'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
                'initial_model': scan.initial_model,
                'fallback_model': scan.fallback_model,
                'prediction': {
                    'predicted_class': prediction.predicted_class,
                    'confidence': prediction.confidence,
                    'risk_score': prediction.risk_score,
                    'model_name': prediction.model_name
                } if prediction else None
            }
        except Scan.DoesNotExist:
            return None
