"""Task 5: authentication, CSRF, ownership, roles, validation and rate limiting."""

import json
import os
from unittest import mock

from django.contrib.auth.models import Group, Permission
from django.test import Client

from User.models import AnalystReview, Scan, ScanFinalDecision
from User.services.fallback_service import FallbackIntegrationService

from .helpers import TenantTestCase

TOKEN = 'svc-token-for-tests-0123456789abcdef0123456789'


def grant(user, *codenames):
    for code in codenames:
        user.user_permissions.add(Permission.objects.using('default').get(codename=code))
    user.refresh_from_db()
    for attr in ('_perm_cache', '_user_perm_cache', '_group_perm_cache'):
        if hasattr(user, attr):
            delattr(user, attr)


class AuthenticationRequiredTests(TenantTestCase):
    PRIVATE_GETS = ['/api/fallback/uncertain-scans/', '/api/fallback/scan-status/1/', '/api/correlation/domain/1/',
                    '/api/correlation/malicious-ips/', '/api/nikhil/investigation/1/']

    def test_private_apis_return_401_json(self):
        for path in self.PRIVATE_GETS:
            response = self.client.get(path)
            self.assertEqual(response.status_code, 401, path)
            self.assertEqual(response.json()['error'], 'authentication_required')
        response = self.client.post('/api/nikhil/submit-review/', '{}', content_type='application/json')
        self.assertEqual(response.status_code, 401)

    def test_wrong_methods_return_405(self):
        self.client.force_login(self.alice)
        self.assertEqual(self.client.post('/api/fallback/uncertain-scans/').status_code, 405)
        self.assertEqual(self.client.get('/api/nikhil/submit-review/').status_code, 405)
        self.assertEqual(self.client.get('/api/fallback/result/').status_code, 405)
        self.assertEqual(self.client.get('/logout').status_code, 405)

    def test_scan_status_enforces_ownership(self):
        own = self.make_scan('user_1', self.alice)
        self.client.force_login(self.alice)
        self.assertEqual(self.client.get(f'/api/fallback/scan-status/{own.id}/').json()['scan']['scan_id'], own.id)
        self.client.force_login(self.bob)
        self.assertEqual(self.client.get(f'/api/fallback/scan-status/{own.id}/').status_code, 404)

    def test_uncertain_scans_only_lists_own(self):
        self.make_scan('user_1', self.alice, status='DEEP_ANALYSIS')
        self.client.force_login(self.bob)
        self.assertEqual(self.client.get('/api/fallback/uncertain-scans/').json()['count'], 0)
        self.client.force_login(self.alice)
        self.assertEqual(self.client.get('/api/fallback/uncertain-scans/').json()['count'], 1)

    def test_correlation_scoped_to_tenant(self):
        scan = self.make_scan('user_1', self.alice)
        domain_id = scan.url.domain_id
        self.client.force_login(self.alice)
        self.assertEqual(self.client.get(f'/api/correlation/domain/{domain_id}/').status_code, 200)
        self.client.force_login(self.bob)
        self.assertEqual(self.client.get(f'/api/correlation/domain/{domain_id}/').status_code, 404)
        self.assertEqual(self.client.get('/api/correlation/malicious-ips/').json()['count'], 0)


class ReviewAuthorizationTests(TenantTestCase):
    def setUp(self):
        super().setUp()
        self.scan = self.make_scan('user_1', self.alice, status='COMPLETED')
        FallbackIntegrationService.persist_final_decision(
            self.scan, {'final_classification': 'Unknown', 'risk_score': 0.5, 'risk_level': 'MEDIUM'}, db='user_1')

    def post(self, client, body):
        return client.post('/api/nikhil/submit-review/', json.dumps(body), content_type='application/json')

    def test_normal_user_forbidden(self):
        self.client.force_login(self.alice)
        response = self.post(self.client, {'scan_id': self.scan.id, 'final_label': 'Phishing'})
        self.assertEqual(response.status_code, 403)
        self.assertFalse(AnalystReview.objects.using('user_1').exists())

    def test_csrf_enforced_for_session_requests(self):
        grant(self.alice, 'submit_review')
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.alice)
        response = self.post(client, {'scan_id': self.scan.id, 'final_label': 'Phishing'})
        self.assertEqual(response.status_code, 403)
        self.assertFalse(AnalystReview.objects.using('user_1').exists())

    def test_analyst_finalizes_needs_review_decision(self):
        grant(self.alice, 'submit_review')
        self.client.force_login(self.alice)
        response = self.post(self.client, {'scan_id': self.scan.id, 'final_label': 'Phishing',
                                           'validation_status': 'VALIDATED', 'review_notes': 'confirmed'})
        self.assertEqual(response.status_code, 200, response.content)
        self.assertTrue(response.json()['final_decision_updated'])
        decision = ScanFinalDecision.objects.using('user_1').get(scan_id=self.scan.id)
        self.assertEqual((decision.final_classification, decision.decision_status), ('Phishing', 'OVERRIDDEN'))
        self.assertEqual(AnalystReview.objects.using('user_1').get().reviewer_id, self.alice.id)

    def test_authoritative_decision_locked_without_override_permission(self):
        ScanFinalDecision.objects.using('user_1').filter(scan_id=self.scan.id).update(
            final_classification='Benign', decision_status='FINAL')
        grant(self.alice, 'submit_review')
        self.client.force_login(self.alice)
        response = self.post(self.client, {'scan_id': self.scan.id, 'final_label': 'Malware'})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(ScanFinalDecision.objects.using('user_1').get(scan_id=self.scan.id).final_classification, 'Benign')
        grant(self.alice, 'override_final_decision')
        self.client.force_login(self.alice)
        self.assertEqual(self.post(self.client, {'scan_id': self.scan.id, 'final_label': 'Malware'}).status_code, 200)

    def test_input_validation(self):
        grant(self.alice, 'submit_review')
        self.client.force_login(self.alice)
        cases = [
            ({'scan_id': self.scan.id, 'final_label': 'Safe'}, 400),
            ({'scan_id': 'x', 'final_label': 'Phishing'}, 400),
            ({'scan_id': True, 'final_label': 'Phishing'}, 400),
            ({'scan_id': self.scan.id, 'final_label': 'Phishing', 'validation_status': 'MAYBE'}, 400),
            ({'scan_id': self.scan.id, 'final_label': 'Phishing', 'review_notes': 'x' * 6000}, 400),
            ({'scan_id': 999, 'final_label': 'Phishing'}, 404),
        ]
        for body, code in cases:
            self.assertEqual(self.post(self.client, body).status_code, code, body)
        self.assertEqual(self.client.post('/api/nikhil/submit-review/', 'not json',
                                          content_type='application/json').status_code, 400)
        self.assertEqual(self.client.post('/api/nikhil/submit-review/', {'a': 1}).status_code, 415)

    def test_setup_roles_command(self):
        from io import StringIO
        from django.core.management import call_command
        call_command('setup_roles', add_analyst='bob', stdout=StringIO())
        self.assertTrue(Group.objects.get(name='Analyst').user_set.filter(username='bob').exists())
        bob = type(self.bob).objects.get(id=self.bob.id)
        self.assertTrue(bob.has_perm('User.submit_review'))
        self.assertFalse(bob.has_perm('User.override_final_decision'))


class ServiceAPITests(TenantTestCase):
    def setUp(self):
        super().setUp()
        from User.models import UserDatabaseRegistry
        UserDatabaseRegistry.objects.using('default').create(user_id=1, username='alice', database_name='x')
        self.scan = self.make_scan('user_1', self.alice)
        patcher = mock.patch('User.db_manager.register_database_connection')
        patcher.start()
        self.addCleanup(patcher.stop)

    def body(self, **extra):
        data = self.fallback_result(self.scan)
        data['tenant_id'] = 'user:1'
        data.update(extra)
        return json.dumps(data)

    def call(self, client=None, token=TOKEN, body=None):
        headers = {'HTTP_AUTHORIZATION': f'Bearer {token}'} if token else {}
        return (client or self.client).post('/api/fallback/result/', body or self.body(),
                                            content_type='application/json', **headers)

    def test_disabled_without_configured_token(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop('FALLBACK_SERVICE_TOKEN', None)
            self.assertEqual(self.call().status_code, 503)

    @mock.patch.dict(os.environ, {'FALLBACK_SERVICE_TOKEN': TOKEN})
    def test_session_auth_alone_is_rejected(self):
        self.client.force_login(self.alice)
        self.assertEqual(self.call(token=None).status_code, 401)
        self.assertEqual(self.call(token='wrong-token').status_code, 403)
        self.assertEqual(Scan.objects.using('user_1').get(id=self.scan.id).status, 'DEEP_ANALYSIS')

    @mock.patch.dict(os.environ, {'FALLBACK_SERVICE_TOKEN': TOKEN})
    def test_valid_token_completes_scan_in_resolved_tenant(self):
        response = self.call()
        self.assertEqual(response.status_code, 200, response.content)
        self.assertEqual(Scan.objects.using('user_1').get(id=self.scan.id).status, 'COMPLETED')
        self.assertEqual(self.call().json()['already_completed'], True)

    @mock.patch.dict(os.environ, {'FALLBACK_SERVICE_TOKEN': TOKEN})
    def test_tenant_and_investigation_identity_validated(self):
        self.assertEqual(self.call(body=self.body(tenant_id='1')).status_code, 400)
        self.assertEqual(self.call(body=self.body(tenant_id='user:2')).status_code, 404)  # no registry row
        self.assertEqual(self.call(body=self.body(investigation_id='not-a-uuid')).status_code, 400)
        self.assertEqual(self.call(body=self.body(
            investigation_id='00000000-0000-0000-0000-000000000000')).status_code, 404)
        self.assertEqual(self.call(body=self.body(final_classification='Safe')).status_code, 400)


class RateLimitTests(TenantTestCase):
    @mock.patch.dict(os.environ, {'RATE_LIMIT_LOGIN_IP': '3/300', 'RATE_LIMIT_LOGIN_USER': '100/300'})
    def test_login_rate_limited_by_ip(self):
        codes = [self.client.post('/login', {'username': 'alice', 'password': 'wrong'}).status_code for _ in range(4)]
        self.assertEqual(codes[:3], [200, 200, 200])
        self.assertEqual(codes[3], 429)

    @mock.patch.dict(os.environ, {'RATE_LIMIT_LOGIN_IP': '100/300', 'RATE_LIMIT_LOGIN_USER': '2/300'})
    def test_login_rate_limited_by_username(self):
        for _ in range(2):
            self.client.post('/login', {'username': 'alice', 'password': 'wrong'})
        response = self.client.post('/login', {'username': 'alice', 'password': self.password})
        self.assertEqual(response.status_code, 429)

    def test_untrusted_forwarded_header_ignored(self):
        with mock.patch.dict(os.environ, {'RATE_LIMIT_LOGIN_IP': '2/300', 'RATE_LIMIT_LOGIN_USER': '100/300',
                                          'TRUSTED_PROXY_COUNT': '0'}):
            for i in range(2):
                self.client.post('/login', {'username': 'x', 'password': 'y'}, HTTP_X_FORWARDED_FOR=f'1.2.3.{i}')
            response = self.client.post('/login', {'username': 'x', 'password': 'y'}, HTTP_X_FORWARDED_FOR='9.9.9.9')
        self.assertEqual(response.status_code, 429)

    @mock.patch.dict(os.environ, {'RATE_LIMIT_SCAN': '1/600'})
    def test_scan_submission_rate_limited(self):
        self.client.force_login(self.alice)
        with mock.patch('User.views.ML_AVAILABLE', False):
            self.client.post('/predict', {'url': 'https://www.example.com/'})
            response = self.client.post('/predict', {'url': 'https://www.example.com/'})
        self.assertEqual(response.status_code, 429)

    @mock.patch.dict(os.environ, {'RATE_LIMIT_API': '2/60'})
    def test_api_rate_limited(self):
        self.client.force_login(self.alice)
        codes = [self.client.get('/api/fallback/uncertain-scans/').status_code for _ in range(3)]
        self.assertEqual(codes, [200, 200, 429])

    @mock.patch.dict(os.environ, {'RATE_LIMIT_ENABLED': 'false', 'RATE_LIMIT_API': '1/60'})
    def test_rate_limit_can_be_disabled(self):
        self.client.force_login(self.alice)
        self.assertEqual([self.client.get('/api/fallback/uncertain-scans/').status_code for _ in range(3)],
                         [200, 200, 200])


class SessionActionTests(TenantTestCase):
    def test_logout_requires_post_with_csrf(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.alice)
        self.assertEqual(client.post('/logout').status_code, 403)
        self.client.force_login(self.alice)
        self.assertEqual(self.client.post('/logout').status_code, 302)
        self.assertEqual(self.client.get('/data').status_code, 302)  # logged out

    def test_clear_history_requires_post(self):
        self.client.force_login(self.alice)
        self.assertEqual(self.client.get('/clear-history').status_code, 405)
