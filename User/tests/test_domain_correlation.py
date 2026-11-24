"""Task 1: domain normalization, historical intelligence and domain/IP correlation."""

import importlib

from django.apps import apps as django_apps
from django.test import SimpleTestCase

from User.models import Domain, IP, Scan, URL
from User.services.correlation_service import CorrelationService
from User.services.domain_normalization import normalize_url, registered_domain_for
from User.services.fallback_service import FallbackIntegrationService
from User.services.historical_intelligence_service import HistoricalIntelligenceService

from .helpers import PUBLIC_IP, TenantTestCase


class NormalizationTests(SimpleTestCase):
    def test_registered_domain_and_parts(self):
        n = normalize_url('https://www.google.co.in/search?q=x')
        self.assertEqual(n.hostname, 'www.google.co.in')
        self.assertEqual(n.registered_domain, 'google.co.in')
        self.assertEqual(n.suffix, 'co.in')
        self.assertEqual(n.subdomain, 'www')
        self.assertEqual(n.domain_label, 'google')

    def test_country_suffixes(self):
        self.assertEqual(registered_domain_for('http://a.b.bbc.co.uk/x'), 'bbc.co.uk')
        self.assertEqual(registered_domain_for('nptel.ac.in/course'), 'nptel.ac.in')
        self.assertEqual(normalize_url('nptel.ac.in').suffix, 'ac.in')

    def test_google_com_and_co_in_are_distinct(self):
        self.assertNotEqual(registered_domain_for('https://google.com'), registered_domain_for('https://google.co.in'))

    def test_uppercase_and_trailing_dot(self):
        self.assertEqual(registered_domain_for('HTTP://WWW.Example.COM./a'), 'example.com')

    def test_internationalized_domain(self):
        n = normalize_url('http://www.bücher.de/')
        self.assertEqual(n.hostname, 'www.xn--bcher-kva.de')
        self.assertEqual(n.registered_domain, 'xn--bcher-kva.de')

    def test_ip_literals(self):
        v4 = normalize_url('http://192.168.10.5/login')
        self.assertTrue(v4.is_ip)
        self.assertEqual(v4.registered_domain, '192.168.10.5')
        self.assertEqual(v4.suffix, '')
        v6 = normalize_url('http://[2001:db8::1]:8080/')
        self.assertTrue(v6.is_ip)
        self.assertEqual(v6.ip, '2001:db8::1')
        self.assertEqual(v6.port, 8080)

    def test_scheme_less_and_suffixless(self):
        self.assertEqual(normalize_url('paypal-account-verify.tk/signin').registered_domain, 'paypal-account-verify.tk')
        self.assertEqual(normalize_url('http://localhost/').registered_domain, 'localhost')

    def test_pari_feature_label_is_unchanged(self):
        """The RF root_domain feature keeps using the original tldextract label."""
        from User import views
        self.assertEqual(views.extract_root_domain('https://www.google.co.in'), 'google')


class HistoricalIntelligenceTests(TenantTestCase):
    def test_domain_history_matches_registered_domain_across_hosts(self):
        previous = self.make_scan('user_1', self.alice, url='https://www.example.com/a', status='COMPLETED')
        FallbackIntegrationService.persist_final_decision(
            previous, {'final_classification': 'Phishing', 'risk_score': 0.9, 'risk_level': 'HIGH'}, db='user_1')
        current = self.make_scan('user_1', self.alice, url='https://login.example.com/verify')

        result = HistoricalIntelligenceService.get_historical_intelligence(
            'https://login.example.com/verify', domain='login.example.com', exclude_scan_id=current.id,
            db_alias='user_1')
        self.assertTrue(result['domain_history']['seen'])
        self.assertEqual(result['target_registered_domain'], 'example.com')
        self.assertEqual(result['known_malicious_in_domain'], 1)
        self.assertEqual(result['domain_history']['scan_count'], 1)  # current scan excluded

    def test_exact_url_history_preserved(self):
        self.make_scan('user_1', self.alice, url='https://www.example.com/a', status='COMPLETED')
        current = self.make_scan('user_1', self.alice, url='https://www.example.com/a')
        result = HistoricalIntelligenceService.get_historical_intelligence(
            'https://www.example.com/a', exclude_scan_id=current.id, db_alias='user_1')
        self.assertTrue(result['exact_url_history']['seen'])
        self.assertEqual(result['exact_url_history']['scan_count'], 1)

    def test_unrelated_country_domain_not_grouped(self):
        self.make_scan('user_1', self.alice, url='https://google.com/', status='COMPLETED')
        result = HistoricalIntelligenceService.get_historical_intelligence('https://google.co.in/', db_alias='user_1')
        self.assertFalse(result['domain_history']['seen'])

    def test_history_is_tenant_isolated(self):
        self.make_scan('user_1', self.alice, url='https://www.example.com/a', status='COMPLETED')
        result = HistoricalIntelligenceService.get_historical_intelligence(
            'https://www.example.com/a', db_alias='user_2')
        self.assertFalse(result['match_found'])

    def test_sql_history_reaches_final_classifier(self):
        from User.services.nikhil.final_classifier import FinalClassifier
        previous = self.make_scan('user_1', self.alice, url='https://www.example.com/a', status='COMPLETED')
        FallbackIntegrationService.persist_final_decision(
            previous, {'final_classification': 'Malware', 'risk_score': 0.9, 'risk_level': 'HIGH'}, db='user_1')
        hist = HistoricalIntelligenceService.get_historical_intelligence('https://example.com/b', db_alias='user_1')
        result = FinalClassifier.classify('Benign', 0.5, {'threat_intelligence': {'local_correlation': hist}})
        self.assertIn('SQL_CORRELATION', result['corroboration']['families_used'])


class IPCorrelationTests(TenantTestCase):
    def _complete(self, url, classification='Phishing', ip=PUBLIC_IP):
        scan = self.make_scan('user_1', self.alice, url=url)
        res = FallbackIntegrationService.process_fallback_result(
            self.fallback_result(scan, classification=classification, ip=ip), db_alias='user_1')
        self.assertTrue(res['success'], res)
        return Scan.objects.using('user_1').get(id=scan.id)

    def test_observed_public_ip_is_recorded_and_linked(self):
        scan = self._complete('https://www.example.com/a')
        self.assertIsNotNone(scan.ip_id)
        ip = IP.objects.using('user_1').get(id=scan.ip_id)
        self.assertEqual(ip.ip_address, PUBLIC_IP)
        self.assertEqual(ip.status, 'MALICIOUS')  # AbuseIPDB score 80 in fixture
        self.assertFalse(IP.objects.using('user_2').exists())

    def test_private_ip_is_never_recorded(self):
        scan = self._complete('https://www.example.com/a', ip='10.0.0.5')
        self.assertIsNone(scan.ip_id)

    def test_domain_ip_bidirectional_correlation(self):
        s1 = self._complete('https://www.example.com/a')
        self._complete('https://example.org/b')
        ip = IP.objects.using('user_1').get(ip_address=PUBLIC_IP)
        domains = set(CorrelationService.get_domains_by_ip(ip.id, db='user_1').values_list('domain_name', flat=True))
        self.assertEqual(domains, {'example.com', 'example.org'})
        domain_id = URL.objects.using('user_1').get(id=s1.url_id).domain_id
        self.assertEqual([i.ip_address for i in CorrelationService.get_ips_by_domain(domain_id, db='user_1')],
                         [PUBLIC_IP])
        mal = list(CorrelationService.get_ips_by_malicious_urls(db='user_1'))
        self.assertEqual(mal[0].malicious_count, 2)
        self.assertEqual(mal[0].domain_count, 2)

    def test_ip_history_in_historical_intelligence(self):
        self._complete('https://www.example.com/a')
        result = HistoricalIntelligenceService.get_historical_intelligence(
            'https://example.org/x', ip=PUBLIC_IP, db_alias='user_1')
        self.assertTrue(result['ip_history']['seen'])
        self.assertEqual(result['ip_history']['scan_count'], 1)
        self.assertIn('example.com', result['ip_history']['co_hosted_domains'])


class DomainDataMigrationTests(TenantTestCase):
    """0013 recovers registered domains from referencing URLs; never guesses or deletes."""

    def _run(self):
        module = importlib.import_module('User.migrations.0013_normalize_registered_domains')

        class Editor:
            class connection:
                alias = 'user_1'
        module.normalize_domains(django_apps, Editor)

    def test_ambiguous_label_is_split_and_unique_label_renamed(self):
        legacy_google = Domain.objects.using('user_1').create(domain_name='google')
        URL.objects.using('user_1').create(url='https://www.google.com/', domain=legacy_google)
        URL.objects.using('user_1').create(url='https://google.co.in/', domain=legacy_google)
        legacy_example = Domain.objects.using('user_1').create(domain_name='example')
        URL.objects.using('user_1').create(url='http://www.example.com/x', domain=legacy_example)
        orphan = Domain.objects.using('user_1').create(domain_name='mystery')

        self._run()
        self._run()  # idempotent

        by_url = {u.url: u.domain.domain_name for u in URL.objects.using('user_1').select_related('domain')}
        self.assertEqual(by_url['https://www.google.com/'], 'google.com')
        self.assertEqual(by_url['https://google.co.in/'], 'google.co.in')
        self.assertEqual(by_url['http://www.example.com/x'], 'example.com')
        renamed = Domain.objects.using('user_1').get(id=legacy_example.id)
        self.assertEqual((renamed.domain_name, renamed.tld), ('example.com', 'com'))
        # Ambiguous legacy row and unverifiable orphan are preserved, not deleted or guessed.
        self.assertTrue(Domain.objects.using('user_1').filter(id=legacy_google.id, domain_name='google').exists())
        self.assertTrue(Domain.objects.using('user_1').filter(id=orphan.id, domain_name='mystery').exists())

    def test_collision_repoints_urls_to_existing_registered_row(self):
        existing = Domain.objects.using('user_1').create(domain_name='example.com', tld='com')
        legacy = Domain.objects.using('user_1').create(domain_name='example')
        u = URL.objects.using('user_1').create(url='https://www.example.com/y', domain=legacy)
        self._run()
        self.assertEqual(URL.objects.using('user_1').get(id=u.id).domain_id, existing.id)
        self.assertTrue(Domain.objects.using('user_1').filter(id=legacy.id).exists())


class PredictDomainStorageTests(TenantTestCase):
    def test_baseline_import_uses_registered_domains(self):
        import tempfile, os
        from django.core.management import call_command
        with tempfile.NamedTemporaryFile('w', suffix='.csv', delete=False, encoding='utf-8') as fh:
            fh.write('url,type\nwww.bbc.co.uk/news,benign\nhttp://sub.example.com/x,phishing\n')
            path = fh.name
        try:
            call_command('import_baseline_urls', csv_file=path, database='user_1', stdout=open(os.devnull, 'w'))
        finally:
            os.remove(path)
        names = dict(Domain.objects.using('user_1').values_list('domain_name', 'tld'))
        self.assertEqual(names, {'bbc.co.uk': 'co.uk', 'example.com': 'com'})
        self.assertFalse(Domain.objects.using('guest_db').exists())
