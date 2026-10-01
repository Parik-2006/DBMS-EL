from django.db import transaction, models
from django.utils import timezone
from User.models import (
    Scan, Prediction, ThreatIndicator, ScanIndicator,
    ScanFallbackResult, ScanEvidenceSummary, ScanAIEvidence,
    ScanFinalDecision
)
import json
import logging


logger = logging.getLogger(__name__)


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
            
            # --- PHASE 3: Write fallback result to ScanFallbackResult. ---
            # The existing pari_prediction row (RandomForest initial result)
            # is LEFT COMPLETELY UNCHANGED. DeepAnalysis data goes to its
            # own table: pari_scan_fallback.
            risk_level = result_data.get('risk_level', None)
            evidence_summary = result_data.get('evidence_summary', '') or ''
            mongo_ref = result_data.get('mongo_document_reference')

            try:
                ScanFallbackResult.objects.get_or_create(
                    scan=scan,
                    defaults={
                        'service_name':           'DeepAnalysis',
                        'classification':         final_classification,
                        'risk_score':             risk_score,
                        'risk_level':             risk_level if risk_level in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] else None,
                        'evidence_summary':       evidence_summary[:500],
                        'mongo_document_reference': mongo_ref,
                    }
                )
            except Exception as fb_err:
                logger.error(
                    "Failed to persist ScanFallbackResult for scan %s: %s",
                    scan.id, fb_err
                )
                errors.append(f"Fallback result DB write failed: {fb_err}")
            # --- END PHASE 3 ---

            # --- PHASE 4: Persist structured evidence summary in MySQL (pari_evidence_summary) ---
            try:
                FallbackIntegrationService.persist_evidence_summaries(scan, result_data)
            except Exception as ev_err:
                logger.error(
                    "Failed to persist evidence summaries for scan %s: %s",
                    scan.id, ev_err
                )
                errors.append(f"Evidence summary DB write failed: {ev_err}")
            # --- END PHASE 4 ---

            # --- PHASE 5: Persist structured AI evidence summary in MySQL (pari_ai_evidence) ---
            try:
                FallbackIntegrationService.persist_ai_evidence(scan, result_data)
            except Exception as ai_err:
                logger.error(
                    "Failed to persist AI evidence for scan %s: %s",
                    scan.id, ai_err
                )
                errors.append(f"AI evidence DB write failed: {ai_err}")
            # --- END PHASE 5 ---
            
            # --- PHASE 10: Persist structured final decision in MySQL (pari_final_decision) ---
            try:
                FallbackIntegrationService.persist_final_decision(scan, result_data)
            except Exception as fd_err:
                logger.error(
                    "Failed to persist final decision for scan %s: %s",
                    scan.id, fd_err
                )
                errors.append(f"Final decision DB write failed: {fd_err}")
            # --- END PHASE 10 ---

            # --- PHASE 8 & 9: Persist threat indicators with explainability provenance ---
            for indicator_str in threat_indicators:
                try:
                    indicator_type = indicator_str.split(':')[0].strip() if ':' in indicator_str else 'OTHER'
                    indicator_value = indicator_str.split(':', 1)[1].strip() if ':' in indicator_str else indicator_str

                    source_comp, ind_reason, ind_sev = FallbackIntegrationService.resolve_indicator_provenance(indicator_type, indicator_value)

                    threat_indicator, created = ThreatIndicator.objects.get_or_create(
                        indicator_type=indicator_type,
                        indicator_value=indicator_value,
                        defaults={'severity': ind_sev}
                    )
                    
                    scan_indicator, created = ScanIndicator.objects.update_or_create(
                        scan=scan,
                        indicator=threat_indicator,
                        defaults={
                            'source_component': source_comp,
                            'reason': ind_reason,
                            'severity': ind_sev,
                        }
                    )
                except Exception as e:
                    errors.append(f"Error processing threat indicator {indicator_str}: {str(e)}")
            # --- END PHASE 8 & 9 ---

            
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
        ).select_related('url', 'prediction').order_by('-created_at')[:limit]
    
    @staticmethod
    def get_scan_status(scan_id):
        """Get current status of a scan, returning initial ML and fallback results separately."""
        try:
            scan = Scan.objects.get(id=scan_id)
            # Initial RandomForest prediction (pari_prediction)
            prediction = scan.prediction if hasattr(scan, 'prediction') else None
            # Fallback result (pari_scan_fallback) — only present if fallback ran
            try:
                fallback = scan.fallback_result
            except ScanFallbackResult.DoesNotExist:
                fallback = None

            return {
                'scan_id': scan.id,
                'url': scan.url.url if scan.url else None,
                'status': scan.status,
                'created_at': scan.created_at.isoformat() if scan.created_at else None,
                'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
                'initial_model': scan.initial_model,
                'fallback_model': scan.fallback_model,
                # Initial RandomForest result — immutable after Phase 3
                'initial_prediction': {
                    'model_name':      prediction.model_name,
                    'predicted_class': prediction.predicted_class,
                    'confidence':      prediction.confidence,
                    'risk_score':      prediction.risk_score,
                    'threshold_used':  prediction.threshold_used,
                    'is_confident':    prediction.is_confident,
                } if prediction else None,
                # Fallback / DeepAnalysis result — separate and independent
                'fallback_result': {
                    'service_name':   fallback.service_name,
                    'classification': fallback.classification,
                    'risk_score':     fallback.risk_score,
                    'risk_level':     fallback.risk_level,
                } if fallback else None,
                # Legacy field — kept for backward compat with callers using 'prediction'
                'prediction': {
                    'predicted_class': prediction.predicted_class,
                    'confidence':      prediction.confidence,
                    'risk_score':      prediction.risk_score,
                    'model_name':      prediction.model_name,
                } if prediction else None,
                # Phase 4 structured evidence summaries
                'evidence_summaries': [
                    {
                        'evidence_family': es.evidence_family,
                        'status':          es.status,
                        'detected':        es.detected,
                        'match_found':     es.match_found,
                        'source_count':    es.source_count,
                        'evidence_count':  es.evidence_count,
                        'severity':        es.severity,
                        'summary':         es.summary,
                    }
                    for es in scan.evidence_summaries.all()
                ],
                # Phase 5 structured AI evidence
                'ai_evidence': {
                    'provider':          scan.ai_evidence.provider,
                    'model':             scan.ai_evidence.model,
                    'status':            scan.ai_evidence.status,
                    'assessment':        scan.ai_evidence.assessment,
                    'confidence':        scan.ai_evidence.confidence,
                    'risk_score':        scan.ai_evidence.risk_score,
                    'ai_required':       scan.ai_evidence.ai_required,
                    'ai_called':         scan.ai_evidence.ai_called,
                    'reasoning_summary': scan.ai_evidence.reasoning_summary,
                } if hasattr(scan, 'ai_evidence') and scan.ai_evidence else None,
            }
        except Scan.DoesNotExist:
            return None

    @staticmethod
    def persist_evidence_summaries(scan, result_data):
        """
        Extract compact structured evidence summary records from Nikhil fallback
        evidence and persist them into pari_evidence_summary (ScanEvidenceSummary).

        Guaranteed idempotent via update_or_create on (scan, evidence_family).
        """
        from User.services.nikhil.mongodb_repository import MongoDBRepository

        evidence_data = result_data.get('evidence_data')
        if not evidence_data:
            try:
                repo = MongoDBRepository()
                evidence_data = repo.get_evidence(scan.id)
                if hasattr(repo, "client") and repo.client:
                    repo.client.close()
            except Exception as e:
                logger.debug("Could not retrieve evidence from MongoDB for scan %s: %s", scan.id, e)
                evidence_data = None

        threat_indicators = result_data.get('threat_indicators', [])
        module_statuses = result_data.get('module_statuses', {})
        threat_intel_display = result_data.get('threat_intel_display', {})

        summaries_to_record = []

        # 1. WEBPAGE
        if evidence_data and 'webpage' in evidence_data:
            wp = evidence_data.get('webpage', {})
            wp_status = wp.get('status', 'PENDING')
            wp_indicators = wp.get('indicators', [])
            wp_findings = wp.get('findings', [])
            wp_detected = bool(wp_indicators or (wp_findings and wp_status == 'SUCCESS')) if wp_status == 'SUCCESS' else None
            wp_severity = 'HIGH' if any(i in ['DEFACEMENT_TEXT', 'PASSWORD_FORM', 'SUSPICIOUS_DOWNLOAD'] for i in wp_indicators) else ('MEDIUM' if wp_indicators else None)
            wp_summary = "; ".join(wp_findings[:3]) if wp_findings else (wp.get('error') or '')
            summaries_to_record.append({
                'family': 'WEBPAGE',
                'source_component': 'WebpageAnalyzer',
                'status': wp_status[:30],
                'detected': wp_detected,
                'match_found': None,
                'source_count': None,
                'evidence_count': len(wp_indicators) if wp_indicators else len(wp_findings),
                'severity': wp_severity,
                'summary': wp_summary[:500],
            })
        else:
            wp_inds = [ind for ind in threat_indicators if ind.startswith('WEBPAGE:')]
            wp_status = module_statuses.get('webpage', 'SUCCESS' if wp_inds else 'UNKNOWN')
            summaries_to_record.append({
                'family': 'WEBPAGE',
                'source_component': 'WebpageAnalyzer',
                'status': wp_status[:30],
                'detected': bool(wp_inds),
                'match_found': None,
                'source_count': None,
                'evidence_count': len(wp_inds),
                'severity': 'HIGH' if wp_inds else None,
                'summary': ("; ".join(wp_inds[:3]))[:500],
            })


        # 2. NETWORK
        if evidence_data and 'network' in evidence_data:
            nw = evidence_data.get('network', {})
            nw_status = nw.get('status', 'PENDING')
            nw_findings = nw.get('network_findings', [])
            nw_is_ip = nw.get('is_ip_address', False)
            nw_detected = bool(nw_findings or nw_is_ip) if nw_status == 'SUCCESS' else None
            nw_severity = 'HIGH' if nw_is_ip else ('MEDIUM' if nw_findings else None)
            nw_summary = "; ".join(nw_findings[:3]) if nw_findings else (nw.get('error') or f"Domain: {nw.get('domain', '')}")
            summaries_to_record.append({
                'family': 'NETWORK',
                'source_component': 'NetworkAnalyzer',
                'status': nw_status[:30],
                'detected': nw_detected,
                'match_found': None,
                'source_count': None,
                'evidence_count': len(nw_findings) + (1 if nw_is_ip else 0),
                'severity': nw_severity,
                'summary': nw_summary[:500],
            })
        else:
            nw_inds = [ind for ind in threat_indicators if ind.startswith('NETWORK:')]
            nw_status = module_statuses.get('network', 'SUCCESS' if nw_inds else 'UNKNOWN')
            summaries_to_record.append({
                'family': 'NETWORK',
                'source_component': 'NetworkAnalyzer',
                'status': nw_status[:30],
                'detected': bool(nw_inds),
                'match_found': None,
                'source_count': None,
                'evidence_count': len(nw_inds),
                'severity': 'HIGH' if nw_inds else None,
                'summary': ("; ".join(nw_inds[:3]))[:500],
            })

        # 3. VISUAL
        if evidence_data and 'visual' in evidence_data:
            vs = evidence_data.get('visual', {})
            vs_status = vs.get('status', 'UNAVAILABLE')
            vs_findings = vs.get('visual_findings', [])
            vs_detected = bool(vs_findings and vs_status == 'SUCCESS') if vs_status == 'SUCCESS' else None
            vs_summary = "; ".join(vs_findings[:3]) if vs_findings else (vs.get('error') or f"Screenshot: {vs.get('screenshot_reference') or 'None'}")
            summaries_to_record.append({
                'family': 'VISUAL',
                'source_component': 'VisualAnalyzer',
                'status': vs_status[:30],
                'detected': vs_detected,
                'match_found': None,
                'source_count': None,
                'evidence_count': len(vs_findings),
                'severity': None,
                'summary': vs_summary[:500],
            })
        else:
            vs_status = module_statuses.get('visual', 'UNAVAILABLE')
            summaries_to_record.append({
                'family': 'VISUAL',
                'source_component': 'VisualAnalyzer',
                'status': vs_status[:30],
                'detected': None,
                'match_found': None,
                'source_count': None,
                'evidence_count': 0,
                'severity': None,
                'summary': 'Visual inspection status: ' + vs_status,
            })

        # 4. THREAT_INTELLIGENCE
        if evidence_data and 'threat_intelligence' in evidence_data:
            ti = evidence_data.get('threat_intelligence', {})
            ti_status = ti.get('status', 'UNAVAILABLE')
            ti_sum = ti.get('summary', {})
            hits = ti_sum.get('positive_hits', 0)
            sources_avail = ti_sum.get('sources_available', 0)
            match_found = bool(hits > 0 or ti_sum.get('known_malicious_ioc') or ti_sum.get('known_malware_url')) if ti_status != 'ERROR' else None
            ti_summary_str = ti_sum.get('threat_intel_ui_summary', '') or ("; ".join(ti.get('threat_findings', [])[:3])) or f"{hits} positive hits across {sources_avail} feeds"
            summaries_to_record.append({
                'family': 'THREAT_INTELLIGENCE',
                'source_component': 'ThreatIntelService',
                'status': ti_status[:30],
                'detected': match_found,
                'match_found': match_found,
                'source_count': sources_avail,
                'evidence_count': hits,
                'severity': 'CRITICAL' if hits > 0 else None,
                'summary': ti_summary_str[:500],
            })
        else:
            ti_status = threat_intel_display.get('status', module_statuses.get('threat_intelligence', 'UNAVAILABLE'))
            hits = threat_intel_display.get('positive_hits', 0)
            sources_avail = threat_intel_display.get('sources_available', 0)
            match_found = bool(hits > 0)
            summaries_to_record.append({
                'family': 'THREAT_INTELLIGENCE',
                'source_component': 'ThreatIntelService',
                'status': ti_status[:30],
                'detected': match_found,
                'match_found': match_found,
                'source_count': sources_avail,
                'evidence_count': hits,
                'severity': 'CRITICAL' if hits > 0 else None,
                'summary': (threat_intel_display.get('ui_summary', 'Threat intelligence checked'))[:500],
            })

        # 5. PROMPT_INJECTION
        if evidence_data and 'prompt_injection' in evidence_data:
            pi = evidence_data.get('prompt_injection', {})
            pi_detected = pi.get('prompt_injection_detected', False)
            patterns = pi.get('matched_patterns', [])
            pi_status = 'ERROR' if pi.get('error') else ('SUCCESS' if 'prompt_injection_detected' in pi else 'NOT_RUN')
            pi_summary = pi.get('explanation', '') or (", ".join(patterns) if patterns else 'No prompt injection detected')
            summaries_to_record.append({
                'family': 'PROMPT_INJECTION',
                'source_component': 'PromptInjectionDetector',
                'status': pi_status[:30],
                'detected': pi_detected,
                'match_found': None,
                'source_count': None,
                'evidence_count': len(patterns),
                'severity': 'CRITICAL' if pi_detected else None,
                'summary': pi_summary[:500],
            })
        else:
            pi_mod_status = module_statuses.get('prompt_injection', 'NOT_DETECTED')
            pi_detected = (pi_mod_status == 'DETECTED')
            summaries_to_record.append({
                'family': 'PROMPT_INJECTION',
                'source_component': 'PromptInjectionDetector',
                'status': 'SUCCESS',
                'detected': pi_detected,
                'match_found': None,
                'source_count': None,
                'evidence_count': 1 if pi_detected else 0,
                'severity': 'CRITICAL' if pi_detected else None,
                'summary': 'Prompt injection detected' if pi_detected else 'No prompt injection detected',
            })

        # 6. SQL_HISTORY
        ti_data = evidence_data.get('threat_intelligence', {}) if evidence_data else {}
        sql_data = ti_data.get('sources', {}).get('local_sql') or ti_data.get('local_correlation', {})
        if sql_data:
            sql_status = sql_data.get('status', 'SUCCESS')
            malicious = sql_data.get('known_malicious_in_domain', 0)
            hist_inds = sql_data.get('historical_indicators', []) or sql_data.get('previous_indicators', [])
            prev_scans = sql_data.get('previous_scans_count', 0)

            # Use match_found from HistoricalIntelligenceService if present
            if 'match_found' in sql_data:
                sql_match = bool(sql_data.get('match_found'))
            else:
                sql_match = bool(malicious > 0 or hist_inds)

            # Severity: HIGH if confirmed malicious history; MEDIUM if mixed outcomes; else None/LOW
            if malicious > 0:
                sql_severity = 'HIGH'
            elif sql_data.get('has_mixed_outcomes'):
                sql_severity = 'MEDIUM'
            elif sql_match and hist_inds:
                sql_severity = 'LOW'
            else:
                sql_severity = None

            # Summary from service if present
            if not sql_match:
                sql_summary = "No previous history found"
                ev_count = 0
                sql_detected = False
            else:
                sql_summary = sql_data.get('summary') or f"{malicious} previous malicious scans, {len(hist_inds)} indicators in history ({prev_scans} prior scans checked)"
                ev_count = malicious + len(hist_inds)
                sql_detected = bool(malicious > 0 or hist_inds)

            summaries_to_record.append({
                'family': 'SQL_HISTORY',
                'source_component': 'HistoricalIntelligenceService',
                'status': sql_status[:30],
                'detected': sql_detected,
                'match_found': sql_match,
                'source_count': None,
                'evidence_count': ev_count,
                'severity': sql_severity,
                'summary': sql_summary[:500],
            })
        else:
            prev_scans = threat_intel_display.get('local_sql_scans', 0)
            malicious = threat_intel_display.get('local_sql_malicious', 0)
            sql_match = bool(malicious > 0)
            summaries_to_record.append({
                'family': 'SQL_HISTORY',
                'source_component': 'HistoricalIntelligenceService',
                'status': 'SUCCESS',
                'detected': sql_match,
                'match_found': sql_match,
                'source_count': None,
                'evidence_count': malicious,
                'severity': 'HIGH' if malicious > 0 else None,
                'summary': f"Local SQL history: {malicious} malicious scans out of {prev_scans} prior scans",
            })

        # 7. TRUSTED_DOMAIN
        td_data = ti_data.get('trusted_domain') or ti_data.get('sources', {}).get('trusted_domain', {})
        if td_data:
            td_known = bool(td_data.get('is_known', False))
            td_status = 'SUCCESS' if td_known else 'NO_MATCH'
            td_summary = f"Category: {td_data.get('category')}, Organization: {td_data.get('organization', 'N/A')}" if td_known else "Domain not listed in trusted directory"
            summaries_to_record.append({
                'family': 'TRUSTED_DOMAIN',
                'source_component': 'TrustedDomainService',
                'status': td_status[:30],
                'detected': None,
                'match_found': td_known,
                'source_count': None,
                'evidence_count': 1 if td_known else 0,
                'severity': None,
                'summary': td_summary[:500],
            })
        else:
            td_category = threat_intel_display.get('trusted_domain')
            td_known = bool(td_category and td_category != 'Not Listed')
            summaries_to_record.append({
                'family': 'TRUSTED_DOMAIN',
                'source_component': 'TrustedDomainService',
                'status': 'SUCCESS' if td_known else 'NO_MATCH',
                'detected': None,
                'match_found': td_known,
                'source_count': None,
                'evidence_count': 1 if td_known else 0,
                'severity': None,
                'summary': f"Trusted domain category: {td_category}" if td_known else "Domain not listed in trusted directory",
            })

        # Persist all via update_or_create (guarantees idempotency on retry)
        for item in summaries_to_record:
            try:
                ScanEvidenceSummary.objects.update_or_create(
                    scan=scan,
                    evidence_family=item['family'],
                    defaults={
                        'source_component': item.get('source_component', ''),
                        'status': item['status'],
                        'detected': item['detected'],
                        'match_found': item['match_found'],
                        'source_count': item['source_count'],
                        'evidence_count': item['evidence_count'],
                        'severity': item['severity'],
                        'summary': item['summary'],
                    }
                )
            except Exception as item_err:
                logger.error(
                    "Failed to write evidence summary %s for scan %s: %s",
                    item['family'], scan.id, item_err
                )

    @staticmethod
    def persist_ai_evidence(scan, result_data):
        """
        Extract compact structured AI evidence summary from Nikhil fallback
        and persist it into pari_ai_evidence (ScanAIEvidence).

        Guaranteed idempotent via update_or_create on scan.
        """
        from User.models import ScanAIEvidence
        from User.services.nikhil.mongodb_repository import MongoDBRepository

        ai_data = None
        evidence_data = result_data.get('evidence_data')
        if evidence_data and 'ai_analysis' in evidence_data:
            ai_data = evidence_data.get('ai_analysis')

        if not ai_data:
            try:
                repo = MongoDBRepository()
                mongo_doc = repo.get_evidence(scan.id)
                if hasattr(repo, "client") and repo.client:
                    repo.client.close()
                if mongo_doc and 'ai_analysis' in mongo_doc:
                    ai_data = mongo_doc.get('ai_analysis')
            except Exception as e:
                logger.debug("Could not retrieve AI evidence from MongoDB for scan %s: %s", scan.id, e)

        ai_display = result_data.get('ai_display', {})
        module_statuses = result_data.get('module_statuses', {})

        if ai_data:
            status = ai_data.get('status', 'NOT_RUN')
            provider = ai_data.get('provider')
            model = ai_data.get('model')
            assessment = ai_data.get('assessment')
            ai_required = bool(ai_data.get('ai_required', False))
            ai_called = bool(ai_data.get('ai_called', False))

            confidence = ai_data.get('confidence')
            if confidence is not None:
                try:
                    confidence = float(confidence)
                except (ValueError, TypeError):
                    confidence = None
            if not ai_called or status != 'SUCCESS':
                if confidence == 0.0:
                    confidence = None

            risk_score = ai_data.get('risk_score')
            if risk_score is not None:
                try:
                    risk_score = float(risk_score)
                except (ValueError, TypeError):
                    risk_score = None

            reasoning = (
                ai_data.get('reasoning_summary', '')
                or ai_data.get('gatekeeper', {}).get('reason', '')
                or ai_data.get('failover_reason', '')
            )
        else:
            status = ai_display.get('status') or module_statuses.get('ai') or 'NOT_RUN'
            provider = ai_display.get('provider')
            model = ai_display.get('model')
            assessment = ai_display.get('assessment')
            ai_required = bool(ai_display.get('ai_required', False))
            ai_called = bool(ai_display.get('ai_called', False))
            confidence = None
            risk_score = None
            reasoning = (
                ai_display.get('reasoning_summary', '')
                or ai_display.get('gatekeeper_reason', '')
                or ai_display.get('failover_reason', '')
            )

        status_val = status[:30] if status else 'NOT_RUN'
        reasoning_str = str(reasoning)[:500] if reasoning else ''

        ScanAIEvidence.objects.update_or_create(
            scan=scan,
            defaults={
                'provider': provider[:50] if provider else None,
                'model': model[:100] if model else None,
                'status': status_val,
                'assessment': assessment[:50] if assessment else None,
                'confidence': confidence,
                'risk_score': risk_score,
                'ai_required': ai_required,
                'ai_called': ai_called,
                'reasoning_summary': reasoning_str,
            }
        )

    @staticmethod
    def resolve_indicator_provenance(indicator_type, indicator_value):
        """
        Map indicator type and value to actual producing subsystem, safe reason, and severity.
        Does NOT invent explanations; uses bounded descriptions matching system detectors.
        """
        type_upper = indicator_type.upper()
        val_upper = indicator_value.upper()

        # Defaults
        source = "NikhilCollector"
        reason = f"Detected {indicator_type.lower()} indicator: {indicator_value}"
        severity = "MEDIUM"

        if type_upper == "URL" or "PARI" in type_upper:
            source = "PARI"
            if "SUSPICIOUS_TOKENS" in val_upper:
                reason = "URL contains multiple suspicious keyword tokens in path or query"
                severity = "MEDIUM"
            elif "PUNYCODE" in val_upper:
                reason = "Punycode or internationalized domain name structure detected"
                severity = "HIGH"
            elif "CREDENTIAL" in val_upper:
                reason = "Credential-themed path pattern detected in URL"
                severity = "HIGH"
            elif "IP_HOSTNAME" in val_upper:
                reason = "IP address used directly as hostname instead of domain"
                severity = "HIGH"
            elif "UNUSUAL_TLD" in val_upper:
                reason = "Unusual or suspicious top-level domain detected"
                severity = "MEDIUM"
            elif "SUSPICIOUS_PORT" in val_upper:
                reason = "Non-standard or suspicious port number detected in URL"
                severity = "MEDIUM"
            else:
                reason = f"URL lexical anomaly detected: {indicator_value}"

        elif type_upper in ["WEBPAGE", "TEXT"]:
            source = "WebpageAnalyzer"
            if "PASSWORD_FORM" in val_upper:
                reason = "Form with password input detected in HTML DOM"
                severity = "HIGH"
            elif "CROSS_DOMAIN_FORM" in val_upper:
                reason = "Cross-domain form submission action detected"
                severity = "HIGH"
            elif "CREDENTIAL_HARVESTING" in val_upper:
                reason = "Credential harvesting phrase detected in page content"
                severity = "HIGH"
            elif "DEFACEMENT" in val_upper:
                reason = "Defacement keyword or header pattern detected in page text"
                severity = "HIGH"
            elif "SUSPICIOUS_DOWNLOAD" in val_upper:
                reason = "Direct executable download link detected in webpage"
                severity = "CRITICAL"
            elif "SUSPICIOUS_IFRAME" in val_upper:
                reason = "Hidden or zero-size iframe element detected"
                severity = "MEDIUM"
            elif "SUSPICIOUS_SCRIPT" in val_upper:
                reason = "Obfuscated or eval JavaScript pattern detected in page scripts"
                severity = "HIGH"
            elif "SUSPICIOUS_REDIRECT" in val_upper:
                reason = "Suspicious client-side cross-domain redirect detected"
                severity = "MEDIUM"
            else:
                reason = f"Webpage structural or content indicator: {indicator_value}"

        elif type_upper in ["NETWORK", "IP", "DNS", "SSL"]:
            source = "NetworkAnalyzer"
            if "IP_ADDRESS" in val_upper:
                reason = "Direct IP address host used without domain name"
                severity = "HIGH"
            elif "SELF_SIGNED" in val_upper or "SSL" in val_upper:
                reason = "Self-signed or invalid SSL certificate detected"
                severity = "MEDIUM"
            elif "SUSPICIOUS_PORT" in val_upper:
                reason = "Suspicious network port active or referenced"
                severity = "MEDIUM"
            else:
                reason = f"Network or transport anomaly: {indicator_value}"

        elif type_upper == "VISUAL":
            source = "VisualAnalyzer"
            reason = f"Visual layout analysis finding: {indicator_value}"
            severity = "MEDIUM"

        elif type_upper in ["PROMPT_INJECTION", "INJECTION"]:
            source = "PromptInjectionDetector"
            reason = "Prompt injection adversarial pattern detected in webpage content"
            severity = "CRITICAL"

        elif "THREATFOX" in type_upper or "THREAT_FOX" in type_upper:
            source = "ThreatFox"
            reason = "Malicious IOC matched in ThreatFox threat database"
            severity = "CRITICAL"
        elif "URLHAUS" in type_upper:
            source = "URLhaus"
            reason = "Malware distribution URL matched in URLhaus feed"
            severity = "CRITICAL"
        elif "ABUSEIPDB" in type_upper:
            source = "AbuseIPDB"
            reason = "High confidence malicious abuse activity reported by AbuseIPDB"
            severity = "HIGH"
        elif type_upper in ["THREAT_INTEL", "THREAT_INTELLIGENCE"]:
            source = "ThreatIntelService"
            reason = f"Threat intelligence match recorded: {indicator_value}"
            severity = "HIGH"

        elif "SQL_HISTORY" in type_upper or "LOCAL_SQL" in type_upper or type_upper == "REPUTATION":
            source = "HistoricalIntelligenceService"
            reason = f"Historical correlation finding: {indicator_value}"
            severity = "HIGH" if "MALICIOUS" in val_upper else "MEDIUM"

        elif "TRUSTED_DOMAIN" in type_upper:
            source = "TrustedDomainService"
            reason = f"Domain listed in trusted directory: {indicator_value}"
            severity = "LOW"

        elif type_upper == "AI":
            source = "Gemini"
            reason = f"AI model flagged suspicious characteristic: {indicator_value}"
            severity = "HIGH"

        return source, reason, severity

    @staticmethod
    def persist_final_decision(scan, result_data):
        """
        Record the official final decision in pari_final_decision (ScanFinalDecision).
        Idempotent via update_or_create on scan.

        Clearly separated from:
        - initial RandomForest prediction (pari_prediction)
        - fallback execution result (pari_scan_fallback)
        - evidence summaries (pari_evidence_summary)
        - AI evidence (pari_ai_evidence)
        """
        final_classification = result_data.get('final_classification', 'Unknown')
        risk_score = float(result_data.get('risk_score', 0.50))
        risk_level = result_data.get('risk_level', 'MEDIUM')
        summary = result_data.get('evidence_summary', '')
        corroboration = result_data.get('corroboration', {})

        # Corroboration details
        corrob_strength = corroboration.get('strength', 'NONE') if corroboration else 'NONE'
        has_conflict = bool(corroboration.get('conflicting', False)) if corroboration else False

        # Calculate distinct contributing evidence families
        families_used = corroboration.get('families_used', []) if corroboration else []
        if families_used:
            family_count = len(set(families_used))
        else:
            # Fallback: count distinct families in ScanEvidenceSummary with detected or match_found True
            family_count = ScanEvidenceSummary.objects.filter(
                scan=scan
            ).filter(
                models.Q(detected=True) | models.Q(match_found=True)
            ).values('evidence_family').distinct().count()

        # Decision status
        if final_classification in ['Unknown', 'Needs Review']:
            decision_status = 'NEEDS_REVIEW'
        else:
            decision_status = 'FINAL'

        decision_method = 'DETERMINISTIC_CORROBORATION'

        ScanFinalDecision.objects.update_or_create(
            scan=scan,
            defaults={
                'final_classification': final_classification,
                'risk_score': round(risk_score, 2),
                'risk_level': risk_level,
                'decision_status': decision_status,
                'decision_method': decision_method,
                'corroboration_strength': corrob_strength,
                'evidence_family_count': family_count,
                'conflict_detected': has_conflict,
                'decision_summary': summary[:500] if summary else f"Final classification: {final_classification}",
            }
        )

    @staticmethod
    def persist_confident_final_decision(scan, predicted_class, confidence, risk_score):
        """
        Record the official final decision for confident RandomForest predictions (confidence >= 0.75).
        Idempotent via update_or_create on scan.
        """
        risk_level = 'LOW' if predicted_class == 'Benign' else ('HIGH' if risk_score >= 0.7 else 'MEDIUM')
        summary = f"High-confidence initial Random Forest prediction ({confidence:.2%})"

        ScanFinalDecision.objects.update_or_create(
            scan=scan,
            defaults={
                'final_classification': predicted_class,
                'risk_score': round(float(risk_score), 2),
                'risk_level': risk_level,
                'decision_status': 'CONFIDENT_ML',
                'decision_method': 'INITIAL_CONFIDENT_PREDICTION',
                'corroboration_strength': 'INITIAL_ML_ONLY',
                'evidence_family_count': 1,
                'conflict_detected': False,
                'decision_summary': summary[:500],
            }
        )
