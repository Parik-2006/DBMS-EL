"""Task 2: tenant-aware transactions, idempotency, scan consistency and history linkage."""

from datetime import timedelta
from unittest import mock

from django.db import transaction
from django.utils import timezone

from User.models import (
    MaliciousBot, Prediction, Scan, ScanAIEvidence, ScanEvidenceSummary, ScanFallbackResult,
    ScanFinalDecision, ScanIndicator, ThreatIndicator,
)
from User.services.fallback_service import FallbackIntegrationService
from User.services.nikhil.mongodb_repository import MongoDBRepository

from .helpers import TenantTestCase


def counts(alias, scan):
    return {
        'fallback': ScanFallbackResult.objects.using(alias).filter(scan_id=scan.id).count(),
        'summaries': ScanEvidenceSummary.objects.using(alias).filter(scan_id=scan.id).count(),
        'ai': ScanAIEvidence.objects.using(alias).filter(scan_id=scan.id).count(),
        'decision': ScanFinalDecision.objects.using(alias).filter(scan_id=scan.id).count(),
        'indicators': ScanIndicator.objects.using(alias).filter(scan_id=scan.id).count(),
    }


class FallbackTransactionTests(TenantTestCase):
    def test_success_writes_all_records_to_the_tenant_db_only(self):
        scan = self.make_scan('user_1', self.alice)
        result = FallbackIntegrationService.process_fallback_result(self.fallback_result(scan), db_alias='user_1')
        self.assertTrue(result['success'], result)
        self.assertEqual(counts('user_1', scan),
                         {'fallback': 1, 'summaries': 7, 'ai': 1, 'decision': 1, 'indicators': 2})
        stored = Scan.objects.using('user_1').get(id=scan.id)
        self.assertEqual(stored.status, 'COMPLETED')
        self.assertEqual(stored.forensic_status, 'STORED')
        self.assertIsNotNone(stored.completed_at)
        for other in ('user_2', 'guest_db'):
            self.assertFalse(ScanFallbackResult.objects.using(other).exists())
            self.assertFalse(ScanFinalDecision.objects.using(other).exists())

    def test_transaction_uses_tenant_alias(self):
        scan = self.make_scan('user_1', self.alice)
        real_atomic = transaction.atomic
        used = []

        def spy(*args, **kwargs):
            used.append(kwargs.get('using', args[0] if args else None))
            return real_atomic(*args, **kwargs)

        with mock.patch('User.services.fallback_service.transaction.atomic', side_effect=spy):
            FallbackIntegrationService.process_fallback_result(self.fallback_result(scan), db_alias='user_1')
        self.assertEqual(set(used), {'user_1'})  # Django's own atomic() calls also use the tenant alias

    def test_failure_rolls_back_everything_and_marks_failed(self):
        scan = self.make_scan('user_1', self.alice)
        with mock.patch.object(FallbackIntegrationService, 'persist_threat_indicators',
                               side_effect=RuntimeError('boom db://secret')):
            result = FallbackIntegrationService.process_fallback_result(self.fallback_result(scan), db_alias='user_1')
        self.assertFalse(result['success'])
        self.assertNotIn('secret', str(result))
        self.assertEqual(counts('user_1', scan), {'fallback': 0, 'summaries': 0, 'ai': 0, 'decision': 0, 'indicators': 0})
        stored = Scan.objects.using('user_1').get(id=scan.id)
        self.assertEqual(stored.status, 'FAILED')
        self.assertIn('RuntimeError', stored.failure_reason)
        # The original ML prediction is preserved.
        self.assertEqual(Prediction.objects.using('user_1').get(scan_id=scan.id).predicted_class, 'Benign')

    def test_retry_after_failure_completes(self):
        scan = self.make_scan('user_1', self.alice)
        with mock.patch.object(FallbackIntegrationService, 'persist_final_decision', side_effect=ValueError('x')):
            FallbackIntegrationService.process_fallback_result(self.fallback_result(scan), db_alias='user_1')
        result = FallbackIntegrationService.process_fallback_result(self.fallback_result(scan), db_alias='user_1')
        self.assertTrue(result['success'], result)
        self.assertEqual(Scan.objects.using('user_1').get(id=scan.id).status, 'COMPLETED')

    def test_reprocessing_completed_scan_is_idempotent_and_non_destructive(self):
        scan = self.make_scan('user_1', self.alice)
        FallbackIntegrationService.process_fallback_result(self.fallback_result(scan), db_alias='user_1')
        before = counts('user_1', scan)
        again = FallbackIntegrationService.process_fallback_result(
            self.fallback_result(scan, classification='Benign'), db_alias='user_1')
        self.assertTrue(again['success'])
        self.assertTrue(again['already_completed'])
        self.assertEqual(counts('user_1', scan), before)
        self.assertEqual(ScanFinalDecision.objects.using('user_1').get(scan_id=scan.id).final_classification, 'Phishing')

    def test_duplicate_indicators_are_not_duplicated(self):
        scan = self.make_scan('user_1', self.alice)
        FallbackIntegrationService.process_fallback_result(
            self.fallback_result(scan, indicators=['WEBPAGE:PASSWORD_FORM', 'WEBPAGE:PASSWORD_FORM']), db_alias='user_1')
        self.assertEqual(ScanIndicator.objects.using('user_1').filter(scan_id=scan.id).count(), 1)
        self.assertEqual(ThreatIndicator.objects.using('user_1').count(), 1)

    def test_validation_failure_changes_nothing(self):
        scan = self.make_scan('user_1', self.alice)
        bad = self.fallback_result(scan, classification='Totally-Safe')
        result = FallbackIntegrationService.process_fallback_result(bad, db_alias='user_1')
        self.assertFalse(result['success'])
        self.assertEqual(Scan.objects.using('user_1').get(id=scan.id).status, 'DEEP_ANALYSIS')

    def test_scan_id_from_another_tenant_is_not_found(self):
        scan = self.make_scan('user_1', self.alice)
        result = FallbackIntegrationService.process_fallback_result(self.fallback_result(scan), db_alias='user_2')
        self.assertFalse(result['success'])
        self.assertFalse(ScanFallbackResult.objects.using('user_1').exists())

    def test_investigation_identity_mismatch_rejected(self):
        scan = self.make_scan('user_1', self.alice)
        data = self.fallback_result(scan, investigation_id='00000000-0000-0000-0000-000000000000')
        self.assertFalse(FallbackIntegrationService.process_fallback_result(data, db_alias='user_1')['success'])

    def test_stale_scans_are_recovered(self):
        stale = self.make_scan('user_1', self.alice, status='DEEP_ANALYSIS')
        fresh = self.make_scan('user_1', self.alice, url='https://example.org/', status='DEEP_ANALYSIS')
        Scan.objects.using('user_1').filter(id=stale.id).update(updated_at=timezone.now() - timedelta(hours=2))
        recovered = FallbackIntegrationService.recover_stale_scans(db='user_1', older_than_minutes=15)
        self.assertEqual(recovered, 1)
        self.assertEqual(Scan.objects.using('user_1').get(id=stale.id).status, 'FAILED')
        self.assertEqual(Scan.objects.using('user_1').get(id=fresh.id).status, 'DEEP_ANALYSIS')

    def test_reconcile_command_dry_run_does_not_write(self):
        from io import StringIO
        from django.core.management import call_command
        stale = self.make_scan('guest_db', None, status='UNCERTAIN')
        Scan.objects.using('guest_db').filter(id=stale.id).update(updated_at=timezone.now() - timedelta(hours=2))
        out = StringIO()
        call_command('reconcile_scans', tenant='guest', stdout=out)
        self.assertIn('stale=1', out.getvalue())
        self.assertEqual(Scan.objects.using('guest_db').get(id=stale.id).status, 'UNCERTAIN')
        call_command('reconcile_scans', tenant='guest', apply=True, stdout=StringIO())
        self.assertEqual(Scan.objects.using('guest_db').get(id=stale.id).status, 'FAILED')


class PredictionPersistenceTests(TenantTestCase):
    def _pipeline(self):
        from User import views
        self.assertTrue(views.train_model())
        return views.pipeline

    def test_initial_prediction_is_atomic_and_not_duplicated(self):
        from User.services.ml_service import MLPredictionService
        from User.models import URL, Domain
        pipeline = self._pipeline()
        dom = Domain.objects.using('user_1').create(domain_name='example.com')
        url = URL.objects.using('user_1').create(url='https://www.example.com/', domain=dom)
        scan = MLPredictionService.create_scan_record(url, user=self.alice, db='user_1')
        first = MLPredictionService.make_prediction(pipeline, url.url, scan, db='user_1')
        second = MLPredictionService.make_prediction(pipeline, url.url, scan, db='user_1')
        self.assertEqual(Prediction.objects.using('user_1').filter(scan_id=scan.id).count(), 1)
        self.assertEqual(first['predicted_class'], second['predicted_class'])
        self.assertFalse(Scan.objects.using('user_2').exists())

    def test_prediction_failure_marks_error_without_partial_rows(self):
        from User.services.ml_service import MLPredictionService
        from User.models import URL, Domain
        dom = Domain.objects.using('user_1').create(domain_name='example.com')
        url = URL.objects.using('user_1').create(url='https://www.example.com/', domain=dom)
        scan = MLPredictionService.create_scan_record(url, user=self.alice, db='user_1')
        broken = mock.MagicMock()
        broken.predict.side_effect = RuntimeError('model broke')
        with self.assertRaises(RuntimeError):
            MLPredictionService.make_prediction(broken, url.url, scan, db='user_1')
        self.assertEqual(Scan.objects.using('user_1').get(id=scan.id).status, 'ERROR')
        self.assertFalse(Prediction.objects.using('user_1').exists())


class PredictViewFlowTests(TenantTestCase):
    """End-to-end /predict with Nikhil mocked (no outbound traffic)."""

    def _nikhil_result(self, data):
        return {
            'scan_id': data['scan_id'], 'investigation_id': data['investigation_id'],
            'analysis_status': 'COMPLETED', 'final_classification': 'Phishing', 'risk_level': 'HIGH',
            'risk_score': 0.88, 'evidence_summary': 'test', 'threat_indicators': ['WEBPAGE:PASSWORD_FORM'],
            'mongo_document_reference': 'oid1', 'forensic_status': 'STORED', 'corroboration': {},
            'module_statuses': {'webpage': 'SUCCESS', 'network': 'FAILED', 'visual': 'UNAVAILABLE', 'threat_intelligence': 'UNAVAILABLE', 'prompt_injection': 'NOT_DETECTED', 'ai': 'NOT_RUN'}, 'evidence_breakdown': {}, 'ai_display': {'status': 'NOT_RUN'}, 'threat_intel_display': {},
            'evidence_data': {'network': {'status': 'FAILED'}},
        }

    def test_uncertain_scan_flow_links_history_to_exact_scan(self):
        self.client.force_login(self.alice)
        calls = []

        def fake_analyze(_self, data):
            calls.append(data)
            return self._nikhil_result(data)

        with mock.patch('User.services.ml_service.get_confidence_threshold', return_value=1.01), \
                mock.patch('User.services.nikhil.nikhil_service.NikhilService.analyze_uncertain_url', fake_analyze):
            r1 = self.client.post('/predict', {'url': 'https://www.example.com/login'})
            r2 = self.client.post('/predict', {'url': 'https://www.example.com/login'})
        self.assertEqual(r1.status_code, 200)
        self.assertEqual(r2.status_code, 200)
        self.assertEqual([c['tenant_id'] for c in calls], ['user:1', 'user:1'])
        self.assertEqual([c['db_alias'] for c in calls], ['user_1', 'user_1'])
        scans = list(Scan.objects.using('user_1').order_by('id'))
        self.assertEqual([s.status for s in scans], ['COMPLETED', 'COMPLETED'])
        history = list(MaliciousBot.objects.using('user_1').order_by('id'))
        self.assertEqual([h.scan_id for h in history], [scans[0].id, scans[1].id])
        from User.models import Domain
        self.assertEqual(list(Domain.objects.using('user_1').values_list('domain_name', 'tld')), [('example.com', 'com')])
        self.assertFalse(Scan.objects.using('user_2').exists())

    def test_nikhil_crash_marks_failed_and_preserves_prediction(self):
        self.client.force_login(self.alice)
        with mock.patch('User.services.ml_service.get_confidence_threshold', return_value=1.01), \
                mock.patch('User.services.nikhil.nikhil_service.NikhilService.analyze_uncertain_url',
                           side_effect=RuntimeError('crash')):
            response = self.client.post('/predict', {'url': 'https://www.example.com/x'})
        self.assertEqual(response.status_code, 200)
        scan = Scan.objects.using('user_1').get()
        self.assertEqual(scan.status, 'FAILED')
        self.assertTrue(Prediction.objects.using('user_1').filter(scan=scan).exists())

    def test_confident_flow(self):
        self.client.force_login(self.alice)
        with mock.patch('User.services.ml_service.get_confidence_threshold', return_value=0.0):
            response = self.client.post('/predict', {'url': 'https://www.example.com/'})
        self.assertEqual(response.status_code, 200)
        scan = Scan.objects.using('user_1').get()
        self.assertEqual(scan.status, 'CONFIDENT')
        self.assertEqual(scan.forensic_status, 'NOT_APPLICABLE')
        self.assertEqual(ScanFinalDecision.objects.using('user_1').get(scan=scan).decision_status, 'CONFIDENT_ML')
        self.assertEqual(MaliciousBot.objects.using('user_1').get().scan_id, scan.id)

    def test_invalid_submissions_rejected(self):
        self.client.force_login(self.alice)
        for bad in ['', 'ftp://example.com/x', 'http://exa mple.com', 'https://' + 'a' * 600 + '.com']:
            response = self.client.post('/predict', {'url': bad})
            self.assertEqual(response.status_code, 400, bad)
        self.assertFalse(Scan.objects.using('user_1').exists())

    def test_ml_unavailable_reports_truthfully(self):
        self.client.force_login(self.alice)
        with mock.patch('User.views.ML_AVAILABLE', False):
            response = self.client.post('/predict', {'url': 'https://www.example.com/'})
        self.assertEqual(response.status_code, 503)
        self.assertNotContains(response, 'appears safe', status_code=503)
        self.assertFalse(Scan.objects.using('user_1').exists())


class HistoryViewTests(TenantTestCase):
    def _history_row(self, scan, alias='user_1', user=None):
        return MaliciousBot.objects.using(alias).create(
            user=user or self.alice, url=scan.url.url, scan=scan, prediction='Initial: x → Fallback: Phishing',
            prediction_type='Phishing', confidence='Initial: 60%, Risk: HIGH')

    def test_each_row_uses_its_own_scan_evidence(self):
        first = self.make_scan('user_1', self.alice, status='COMPLETED')
        second = self.make_scan('user_1', self.alice, status='COMPLETED')
        for s in (first, second):
            Scan.objects.using('user_1').filter(id=s.id).update(fallback_model='DeepAnalysis')
            s.fallback_model = 'DeepAnalysis'
        repo = MongoDBRepository()
        repo.store_evidence({'scan_id': first.id, 'threat_intelligence': {'sources': {'urlhaus': {'status': 'SUCCESS'}}}},
                            tenant_id='user:1')
        repo.store_evidence({'scan_id': second.id, 'threat_intelligence': {'sources': {'urlhaus': {'status': 'NO_MATCH'}}}},
                            tenant_id='user:1')
        self._history_row(first)
        self._history_row(second)
        legacy = MaliciousBot.objects.using('user_1').create(user=self.alice, url=first.url.url,
                                                              prediction='Deep Analysis Result: X', prediction_type='Unknown')
        self.client.force_login(self.alice)
        response = self.client.get('/data')
        rows = {row['id']: row for row in response.context['data']}
        self.assertEqual(len(rows), 3)
        by_scan = {row['threat_intel']['urlhaus'] for row in rows.values() if row['threat_intel']}
        self.assertEqual(by_scan, {'SUCCESS', 'NO_MATCH'})
        self.assertIsNone(rows[legacy.id]['threat_intel'])  # legacy rows are never guessed

    def test_evidence_lookup_failure_does_not_drop_rows(self):
        scan = self.make_scan('user_1', self.alice, status='COMPLETED')
        Scan.objects.using('user_1').filter(id=scan.id).update(fallback_model='DeepAnalysis')
        self._history_row(Scan.objects.using('user_1').get(id=scan.id))
        self.client.force_login(self.alice)
        with mock.patch.object(MongoDBRepository, 'get_evidence', side_effect=RuntimeError('mongo down')):
            response = self.client.get('/data')
        self.assertEqual(len(response.context['data']), 1)

    def test_history_is_tenant_isolated(self):
        scan = self.make_scan('user_1', self.alice, status='COMPLETED')
        self._history_row(scan)
        self.client.force_login(self.bob)
        response = self.client.get('/data')
        self.assertEqual(response.context['data'], [])
