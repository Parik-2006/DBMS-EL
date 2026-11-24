"""Task 3: MongoDB / cache / screenshot / investigation tenant isolation with colliding scan ids."""

import os
from io import StringIO
from unittest import mock

from django.core.management import call_command
from django.test import SimpleTestCase

from User.models import ScanFallbackResult
from User.services.nikhil.mongodb_repository import INDEX_SPECS, MongoDBRepository, TenantScopedCache
from User.services.nikhil.visual_analyzer import VisualAnalyzer

from .helpers import FakeCollection, TenantTestCase


class MongoIsolationTests(SimpleTestCase):
    def setUp(self):
        MongoDBRepository._fallback_cache.clear()
        self.coll = FakeCollection()
        self.repo = MongoDBRepository(collection=self.coll)

    def test_identical_scan_ids_do_not_overwrite(self):
        self.repo.store_evidence({'scan_id': 5, 'url': 'https://a.example.com', 'note': 'A'}, tenant_id='user:1')
        self.repo.store_evidence({'scan_id': 5, 'url': 'https://b.example.com', 'note': 'B'}, tenant_id='user:2')
        self.assertTrue(self.repo.last_store_durable)
        self.assertEqual(len(self.coll.docs), 2)
        self.assertEqual(self.repo.get_evidence(5, tenant_id='user:1')['note'], 'A')
        self.assertEqual(self.repo.get_evidence(5, tenant_id='user:2')['note'], 'B')

    def test_retrieval_requires_tenant(self):
        self.repo.store_evidence({'scan_id': 5}, tenant_id='user:1')
        with self.assertRaises(ValueError):
            self.repo.get_evidence(5)
        with self.assertRaises(ValueError):
            self.repo.store_evidence({'scan_id': 5})
        with self.assertRaises(ValueError):
            self.repo.get_evidence(5, tenant_id='1')  # client-style raw id is not a tenant id
        self.assertIsNone(self.repo.get_evidence(5, tenant_id='user:3'))

    def test_upsert_updates_own_document_only(self):
        self.repo.store_evidence({'scan_id': 7, 'v': 1}, tenant_id='user:1')
        self.repo.store_evidence({'scan_id': 7, 'v': 9}, tenant_id='user:2')
        self.repo.store_evidence({'scan_id': 7, 'v': 2}, tenant_id='user:1')
        self.assertEqual(self.repo.get_evidence(7, tenant_id='user:1')['v'], 2)
        self.assertEqual(self.repo.get_evidence(7, tenant_id='user:2')['v'], 9)

    def test_legacy_and_quarantined_documents_are_never_returned(self):
        self.coll.docs.append({'_id': 'legacy1', 'scan_id': 11, 'url': 'x'})
        self.coll.docs.append({'_id': 'q1', 'scan_id': 12, 'tenant_id': 'user:1', 'quarantined': True})
        self.assertIsNone(self.repo.get_evidence(11, tenant_id='user:1'))
        self.assertIsNone(self.repo.get_evidence(12, tenant_id='user:1'))

    def test_legacy_backfill_and_quarantine_are_non_destructive(self):
        self.coll.docs.append({'_id': 'legacy1', 'scan_id': 11})
        self.assertTrue(self.repo.backfill_legacy_owner('legacy1', 'user:1', 'abc'))
        self.assertFalse(self.repo.backfill_legacy_owner('legacy1', 'user:2'))  # already scoped
        self.coll.docs.append({'_id': 'legacy2', 'scan_id': 12})
        self.assertTrue(self.repo.quarantine_legacy_document('legacy2', 'conflict'))
        self.assertEqual(len(self.coll.docs), 2)
        self.assertEqual(self.repo.get_evidence(11, tenant_id='user:1')['investigation_id'], 'abc')

    def test_secrets_and_cookies_redacted_before_storage(self):
        with mock.patch.dict(os.environ, {'GEMINI_API_KEY': 'AIzaSyFAKEKEYFORTESTS000000000000000'}):
            self.repo.store_evidence({
                'scan_id': 1,
                'webpage': {'response_headers': {'Set-Cookie': 'session=abc', 'Server': 'nginx'}},
                'ai_analysis': {'attempt_log': [{'error': 'url ...?key=AIzaSyFAKEKEYFORTESTS000000000000000 failed'}]},
            }, tenant_id='user:1')
        doc = self.coll.docs[0]
        self.assertEqual(doc['webpage']['response_headers']['Set-Cookie'], '[REDACTED]')
        self.assertEqual(doc['webpage']['response_headers']['Server'], 'nginx')
        self.assertNotIn('AIzaSyFAKE', str(doc))

    def test_mongo_failure_keeps_isolation_and_reports_non_durable(self):
        self.coll.fail = True
        ref = self.repo.store_evidence({'scan_id': 3, 'note': 'A'}, tenant_id='user:1')
        self.assertTrue(ref.startswith('local-cache:'))
        self.assertFalse(self.repo.last_store_durable)
        self.assertFalse(MongoDBRepository.is_durable_reference(ref))
        self.assertEqual(self.repo.get_evidence(3, tenant_id='user:1')['note'], 'A')
        self.assertIsNone(self.repo.get_evidence(3, tenant_id='user:2'))

    def test_index_definitions(self):
        specs = {s['name']: s for s in INDEX_SPECS}
        self.assertEqual(specs['uq_tenant_scan']['keys'], [('tenant_id', 1), ('scan_id', 1)])
        self.assertTrue(specs['uq_tenant_scan']['unique'])
        self.assertEqual(specs['uq_tenant_scan']['partialFilterExpression'], {'tenant_id': {'$exists': True}})
        self.assertTrue(specs['uq_investigation_id']['unique'])
        self.assertEqual(self.repo.ensure_indexes(), ['uq_tenant_scan', 'uq_investigation_id'])
        self.assertTrue(all(opts['unique'] for _, opts in self.coll.indexes))

    def test_no_index_creation_on_normal_use(self):
        self.repo.store_evidence({'scan_id': 1}, tenant_id='user:1')
        self.assertEqual(self.coll.indexes, [])


class CacheTests(SimpleTestCase):
    def test_cache_is_tenant_keyed_bounded_and_copies(self):
        cache = TenantScopedCache(max_entries=2)
        doc = {'v': 1}
        cache.put('user:1', 1, doc)
        doc['v'] = 99
        self.assertEqual(cache.get('user:1', 1)['v'], 1)
        self.assertIsNone(cache.get('user:2', 1))
        cache.put('user:1', 2, {})
        cache.put('user:1', 3, {})
        self.assertEqual(len(cache), 2)
        self.assertIsNone(cache.get('user:1', 1))
        with self.assertRaises(ValueError):
            cache.put(None, 1, {})

    def test_cache_thread_safety(self):
        import threading
        cache = TenantScopedCache(max_entries=50)
        def worker(t):
            for i in range(200):
                cache.put(f'user:{t}', i, {'t': t})
                got = cache.get(f'user:{t}', i)
                assert got is None or got['t'] == t
        threads = [threading.Thread(target=worker, args=(t,)) for t in range(1, 5)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        self.assertLessEqual(len(cache), 50)


class ScreenshotAndInvestigationIsolationTests(TenantTestCase):
    def _screenshot(self, alias, user, tenant):
        scan = self.make_scan(alias, user, status='COMPLETED')
        path, ref = VisualAnalyzer.screenshot_location(tenant, scan.investigation_id)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'wb') as fh:
            fh.write(b'\x89PNG ' + tenant.encode())
        return scan, ref

    def test_scan_ids_collide_but_investigation_ids_differ(self):
        a = self.make_scan('user_1', self.alice)
        b = self.make_scan('user_2', self.bob)
        self.assertEqual(a.id, b.id)
        self.assertNotEqual(a.investigation_id, b.investigation_id)

    def test_owner_can_fetch_screenshot(self):
        _, ref = self._screenshot('user_1', self.alice, 'user:1')
        self.client.force_login(self.alice)
        response = self.client.get(ref)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(b''.join(response.streaming_content), b'\x89PNG user:1')

    def test_other_user_cannot_fetch_screenshot_even_with_same_scan_id(self):
        _, ref_a = self._screenshot('user_1', self.alice, 'user:1')
        self._screenshot('user_2', self.bob, 'user:2')  # bob has a scan with the same numeric id
        self.client.force_login(self.bob)
        self.assertEqual(self.client.get(ref_a).status_code, 404)

    def test_anonymous_legacy_and_traversal_rejected(self):
        _, ref = self._screenshot('user_1', self.alice, 'user:1')
        self.assertEqual(self.client.get(ref).status_code, 302)
        self.client.force_login(self.alice)
        for bad in ['/media/screenshots/scan_1_1700000000.png', '/media/screenshots/..%2F..%2Fsettings.py',
                    '/media/screenshots/' + 'g' * 32 + '.png']:
            self.assertEqual(self.client.get(bad).status_code, 404, bad)

    def test_investigation_detail_returns_only_own_evidence(self):
        a = self.make_scan('user_1', self.alice, status='COMPLETED')
        b = self.make_scan('user_2', self.bob, status='COMPLETED')
        repo = MongoDBRepository()
        repo.store_evidence({'scan_id': a.id, 'owner': 'alice'}, tenant_id='user:1')
        repo.store_evidence({'scan_id': b.id, 'owner': 'bob'}, tenant_id='user:2')
        self.client.force_login(self.bob)
        payload = self.client.get(f'/api/nikhil/investigation/{b.id}/').json()
        self.assertEqual(payload['deep_analysis_evidence']['owner'], 'bob')
        self.assertEqual(payload['investigation_id'], str(b.investigation_id))
        self.client.force_login(self.alice)
        self.assertEqual(self.client.get(f'/api/nikhil/investigation/{a.id}/').json()['deep_analysis_evidence']['owner'],
                         'alice')

    def test_investigation_detail_requires_ownership(self):
        foreign = self.make_scan('user_1', self.bob, status='COMPLETED')  # row owned by another user id
        self.client.force_login(self.alice)
        self.assertEqual(self.client.get(f'/api/nikhil/investigation/{foreign.id}/').status_code, 404)


class LegacyAuditCommandTests(TenantTestCase):
    def test_audit_backfills_only_verifiable_documents(self):
        from User.models import UserDatabaseRegistry
        UserDatabaseRegistry.objects.using('default').create(user_id=1, username='alice', database_name='db1')
        UserDatabaseRegistry.objects.using('default').create(user_id=2, username='bob', database_name='db2')
        a = self.make_scan('user_1', self.alice, url='https://www.example.com/a', status='COMPLETED')
        b = self.make_scan('user_2', self.bob, url='https://example.org/b', status='COMPLETED')
        ScanFallbackResult.objects.using('user_1').create(scan=a, classification='Phishing', risk_score=0.9,
                                                          mongo_document_reference='legacyA')
        ScanFallbackResult.objects.using('user_2').create(scan=b, classification='Benign', risk_score=0.1,
                                                          mongo_document_reference='legacyB')
        coll = FakeCollection()
        coll.docs = [
            {'_id': 'legacyA', 'scan_id': a.id, 'url': 'https://www.example.com/a'},   # verifiable -> alice
            {'_id': 'legacyB', 'scan_id': b.id, 'url': 'https://tampered.example.com'},  # url mismatch
            {'_id': 'legacyC', 'scan_id': 99},                                          # no owner
        ]
        with mock.patch('User.services.nikhil.mongodb_repository.MongoDBRepository.__init__',
                        lambda self, collection=None: (setattr(self, 'collection', coll),
                                                       setattr(self, 'last_store_durable', False))[0]), \
                mock.patch('User.security.tenancy.register_database_connection', create=True), \
                mock.patch('User.db_manager.register_database_connection'):
            out = StringIO()
            call_command('mongo_tenant_maintenance', audit_legacy=True, stdout=out)
            self.assertTrue(all('tenant_id' not in d for d in coll.docs))  # dry-run wrote nothing
            call_command('mongo_tenant_maintenance', audit_legacy=True, apply=True, stdout=out)
        docs = {d['_id']: d for d in coll.docs}
        self.assertEqual(docs['legacyA']['tenant_id'], 'user:1')
        self.assertEqual(docs['legacyA']['investigation_id'], str(a.investigation_id))
        self.assertNotIn('tenant_id', docs['legacyB'])
        self.assertNotIn('tenant_id', docs['legacyC'])
        self.assertEqual(len(coll.docs), 3)
