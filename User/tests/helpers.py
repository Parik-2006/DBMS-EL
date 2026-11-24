"""Shared fixtures for Phase 1 tests (no network, no production databases)."""

import copy
import itertools
import os
import shutil
import unittest
from unittest import mock

from django.contrib.auth.models import User
from django.core.cache import cache
from django.test import TestCase

from User.security import outbound

PUBLIC_IP = '93.184.216.34'

# Deterministic DNS: synthetic names only; nothing reaches a real resolver.
FAKE_DNS = {
    'example.com': ['93.184.216.34'],
    'www.example.com': ['93.184.216.34'],
    'cdn.example.com': ['93.184.216.36'],
    'example.org': ['93.184.216.35'],
    'internal.example.net': ['10.0.0.5'],
    'meta.example.net': ['169.254.169.254'],
    'mixed.example.net': ['93.184.216.34', '192.168.1.10'],
    'v6.example.org': ['2606:2800:220:1:248:1893:25c8:1946'],
    'loop6.example.org': ['::1'],
    'mapped.example.org': ['::ffff:127.0.0.1'],
}


def fake_resolver(host, port):
    if host not in FAKE_DNS:
        raise OSError('NXDOMAIN (fake resolver)')
    return list(FAKE_DNS[host])


class FakeResult:
    def __init__(self, upserted_id=None, modified_count=0):
        self.upserted_id = upserted_id
        self.modified_count = modified_count


class FakeCursor(list):
    def limit(self, n):
        return FakeCursor(self[:n])


class FakeCollection:
    """Minimal in-memory stand-in for a pymongo collection."""

    _ids = itertools.count(1)

    def __init__(self):
        self.docs = []
        self.indexes = []
        self.fail = False

    def _check(self):
        if self.fail:
            from User.services.nikhil.mongodb_repository import PyMongoError
            raise PyMongoError('simulated MongoDB outage')

    @staticmethod
    def _match(doc, flt):
        for key, cond in flt.items():
            if isinstance(cond, dict):
                if '$exists' in cond and ((key in doc) != cond['$exists']):
                    return False
                if '$ne' in cond and doc.get(key) == cond['$ne']:
                    return False
            elif doc.get(key) != cond:
                return False
        return True

    def update_one(self, flt, update, upsert=False):
        self._check()
        for doc in self.docs:
            if self._match(doc, flt):
                doc.update(copy.deepcopy(update.get('$set', {})))
                return FakeResult(None, 1)
        if not upsert:
            return FakeResult(None, 0)
        new = {'_id': f"oid{next(self._ids)}"}
        new.update({k: v for k, v in flt.items() if not isinstance(v, dict)})
        new.update(copy.deepcopy(update.get('$setOnInsert', {})))
        new.update(copy.deepcopy(update.get('$set', {})))
        self.docs.append(new)
        return FakeResult(new['_id'], 0)

    def find_one(self, flt, projection=None):
        self._check()
        for doc in self.docs:
            if self._match(doc, flt):
                return copy.deepcopy(doc)
        return None

    def find(self, flt, projection=None):
        self._check()
        return FakeCursor(copy.deepcopy(d) for d in self.docs if self._match(d, flt))

    def count_documents(self, flt, limit=0):
        self._check()
        return sum(1 for d in self.docs if self._match(d, flt))

    def delete_one(self, flt):
        self._check()
        for i, doc in enumerate(self.docs):
            if self._match(doc, flt):
                del self.docs[i]
                return FakeResult(None, 1)
        return FakeResult(None, 0)

    def create_index(self, keys, **options):
        self.indexes.append((keys, options))
        return options.get('name')


def _route_db(user):
    if user is not None and getattr(user, 'is_authenticated', False):
        return f"user_{user.id}"
    return 'guest_db'


def isolated_test_settings_active():
    from django.conf import settings
    dbs = settings.DATABASES
    return all(alias in dbs and dbs[alias]['ENGINE'].endswith('sqlite3')
               for alias in ('default', 'guest_db', 'user_1', 'user_2'))


ISOLATED = isolated_test_settings_active()


@unittest.skipUnless(ISOLATED, 'requires --settings=MaliciousBot.settings_test (isolated SQLite tenants)')
class TenantTestCase(TestCase):
    """Two real tenants: alice -> user_1, bob -> user_2 (separate SQLite DBs)."""

    # Never ask the runner for (production) MySQL test databases.
    databases = '__all__' if ISOLATED else set()
    password = 'Str0ng!Passw0rd#2026'

    def setUp(self):
        super().setUp()
        patcher = mock.patch('User.middleware.ensure_user_database', side_effect=_route_db)
        patcher.start()
        self.addCleanup(patcher.stop)
        outbound.set_resolver(fake_resolver)
        self.addCleanup(outbound.set_resolver, None)
        cache.clear()
        from User.services.nikhil.mongodb_repository import MongoDBRepository
        MongoDBRepository._fallback_cache.clear()
        self.alice = User.objects.create_user(id=1, username='alice', email='alice@example.test', password=self.password)
        self.bob = User.objects.create_user(id=2, username='bob', email='bob@example.test', password=self.password)

    def tearDown(self):
        from django.conf import settings
        shutil.rmtree(settings.MEDIA_ROOT, ignore_errors=True)
        super().tearDown()

    # --- data builders -------------------------------------------------
    @staticmethod
    def make_scan(alias, user, url='https://www.example.com/login', status='DEEP_ANALYSIS',
                  predicted='Benign', confidence=0.6):
        from User.models import Domain, Prediction, Scan, URL
        from User.services.domain_normalization import normalize_url
        norm = normalize_url(url)
        domain, _ = Domain.objects.using(alias).get_or_create(domain_name=norm.registered_domain,
                                                              defaults={'tld': norm.suffix or None})
        url_obj, _ = URL.objects.using(alias).get_or_create(url=url, defaults={'domain': domain})
        scan = Scan.objects.using(alias).create(user_id=user.id if user else None, url=url_obj, status=status)
        Prediction.objects.using(alias).create(scan=scan, model_name='RandomForest', predicted_class=predicted,
                                               confidence=confidence, risk_score=1 - confidence,
                                               probabilities={}, threshold_used=0.75, is_confident=False)
        return scan

    @staticmethod
    def fallback_result(scan, classification='Phishing', ip=PUBLIC_IP, indicators=None, **extra):
        data = {
            'scan_id': scan.id,
            'investigation_id': str(scan.investigation_id),
            'analysis_status': 'COMPLETED',
            'final_classification': classification,
            'risk_level': 'HIGH',
            'risk_score': 0.88,
            'evidence_summary': 'Confirmed Phishing: test',
            'threat_indicators': indicators if indicators is not None else
            ['WEBPAGE:PASSWORD_FORM', 'TEXT:CREDENTIAL_HARVESTING'],
            'mongo_document_reference': 'oid-test',
            'forensic_status': 'STORED',
            'corroboration': {'strength': 'MODERATE', 'families_used': ['WEBPAGE', 'TEXT'], 'conflicting': False},
            'evidence_data': {
                'webpage': {'status': 'SUCCESS', 'indicators': ['PASSWORD_FORM'], 'findings': ['Form with password']},
                'network': {'status': 'SUCCESS', 'network_findings': [], 'is_ip_address': False,
                            'ip_resolution': {'primary_ip': ip}},
                'visual': {'status': 'UNAVAILABLE', 'visual_findings': []},
                'threat_intelligence': {'status': 'SUCCESS', 'summary': {'positive_hits': 0, 'sources_available': 3},
                                        'sources': {'abuseipdb': {'status': 'SUCCESS', 'abuse_confidence_score': 80,
                                                                  'country_code': 'US'}}},
                'prompt_injection': {'prompt_injection_detected': False, 'matched_patterns': []},
                'ai_analysis': {'status': 'NOT_RUN', 'ai_required': False, 'ai_called': False},
            },
        }
        data.update(extra)
        return data
