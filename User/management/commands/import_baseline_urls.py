import csv
import os
from urllib.parse import urlparse
from django.core.management.base import BaseCommand
from django.db import transaction
from User.models import Domain, URL

class Command(BaseCommand):
    help = 'Import baseline URLs from Phishing.csv into database'

    def add_arguments(self, parser):
        parser.add_argument(
            '--csv-file',
            type=str,
            default='static/dataset/Phishing.csv',
            help='Path to CSV file (default: static/dataset/Phishing.csv)'
        )
        parser.add_argument(
            '--clear',
            action='store_true',
            help='Clear existing baseline URLs before import'
        )

    def extract_domain(self, url):
        """Extract domain from URL"""
        try:
            if not url.startswith(('http://', 'https://', '//')):
                url = 'https://' + url
            parsed = urlparse(url)
            netloc = parsed.netloc or parsed.path
            if netloc.startswith('www.'):
                netloc = netloc[4:]
            return netloc.split('/')[0].lower()
        except Exception as e:
            self.stdout.write(self.style.WARNING(f"Error extracting domain from {url}: {e}"))
            return None

    def extract_tld(self, domain):
        """Extract TLD from domain"""
        try:
            parts = domain.split('.')
            if len(parts) >= 2:
                return '.' + parts[-1].lower()
            return None
        except Exception:
            return None

    @transaction.atomic
    def handle(self, *args, **options):
        csv_file = options['csv_file']
        clear_existing = options['clear']

        if not os.path.exists(csv_file):
            self.stdout.write(self.style.ERROR(f"CSV file not found: {csv_file}"))
            return

        if clear_existing:
            self.stdout.write("Clearing existing baseline URLs...")
            URL.objects.filter(source='BASELINE').delete()
            self.stdout.write(self.style.SUCCESS("Cleared existing baseline URLs"))

        stats = {
            'total': 0,
            'imported': 0,
            'duplicates': 0,
            'errors': 0,
            'by_class': {'benign': 0, 'phishing': 0, 'malware': 0, 'defacement': 0},
            'unique_domains': 0,
            'new_domains': 0,
        }

        self.stdout.write("Starting baseline URL import...")
        self.stdout.write(f"Reading from: {csv_file}")

        domains_cache = {}
        domains_to_create = []

        try:
            with open(csv_file, 'r', encoding='utf-8-sig', errors='ignore') as f:
                reader = csv.DictReader(f)
                
                for row_num, row in enumerate(reader, start=2):
                    url = row.get('url', '').strip()
                    url_type = row.get('type', '').strip().lower()

                    if not url or not url_type:
                        stats['errors'] += 1
                        continue

                    stats['total'] += 1

                    if url_type in stats['by_class']:
                        stats['by_class'][url_type] += 1

                    domain_name = self.extract_domain(url)
                    if not domain_name:
                        stats['errors'] += 1
                        continue

                    if domain_name not in domains_cache:
                        domains_cache[domain_name] = self.extract_tld(domain_name)
                        stats['unique_domains'] += 1

                    url_exists = URL.objects.filter(url=url, source='BASELINE').exists()
                    if url_exists:
                        stats['duplicates'] += 1
                        continue

                    try:
                        domain_obj, created = Domain.objects.get_or_create(
                            domain_name=domain_name,
                            defaults={'tld': domains_cache[domain_name], 'status': 'UNKNOWN'}
                        )
                        if created:
                            stats['new_domains'] += 1

                        url_obj, created = URL.objects.get_or_create(
                            url=url,
                            defaults={
                                'domain': domain_obj,
                                'source': 'BASELINE',
                                'baseline_label': url_type
                            }
                        )
                        
                        if created:
                            stats['imported'] += 1
                        else:
                            stats['duplicates'] += 1

                    except Exception as e:
                        stats['errors'] += 1
                        self.stdout.write(self.style.WARNING(f"Error importing URL {url}: {e}"))

                    if row_num % 50 == 0:
                        self.stdout.write(f"Processed {row_num} rows...")

        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Error reading CSV file: {e}"))
            return

        self.stdout.write("\n" + "="*60)
        self.stdout.write(self.style.SUCCESS("BASELINE URL IMPORT COMPLETE"))
        self.stdout.write("="*60)
        self.stdout.write(f"\nTotal rows in CSV:           {stats['total']}")
        self.stdout.write(f"Successfully imported:       {stats['imported']}")
        self.stdout.write(f"Duplicates (skipped):        {stats['duplicates']}")
        self.stdout.write(f"Errors:                      {stats['errors']}")
        self.stdout.write(f"\nClass Distribution:")
        for url_class, count in stats['by_class'].items():
            self.stdout.write(f"  {url_class.capitalize():15s}: {count:3d}")
        self.stdout.write(f"\nDomain Statistics:")
        self.stdout.write(f"  Unique domains:            {stats['unique_domains']}")
        self.stdout.write(f"  New domains created:       {stats['new_domains']}")
        
        final_url_count = URL.objects.filter(source='BASELINE').count()
        final_domain_count = Domain.objects.count()
        self.stdout.write(f"\nDatabase State:")
        self.stdout.write(f"  Total baseline URLs:       {final_url_count}")
        self.stdout.write(f"  Total domains:             {final_domain_count}")
        self.stdout.write("="*60)
