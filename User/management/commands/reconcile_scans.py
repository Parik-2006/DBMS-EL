"""
Reconcile scan state across MySQL tenants and MongoDB (Phase 1).

MySQL and MongoDB never share a transaction. This command repairs the gaps:

1. Stale scans: UNCERTAIN / DEEP_ANALYSIS older than --stale-minutes (worker
   killed, timeout, crash) -> FAILED with a recovery reason. The initial ML
   prediction is preserved.
2. Forensic status: scans recorded as CACHE_ONLY / PENDING are checked against
   MongoDB using the tenant-scoped identity. Found -> STORED; CACHE_ONLY not
   found -> MISSING (the volatile cache did not survive). PENDING legacy scans
   that are not found stay PENDING (see mongo_tenant_maintenance).

Dry-run by default; pass --apply to write. Never deletes anything.
"""

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from datetime import timedelta


class Command(BaseCommand):
    help = "Recover stale scans and reconcile MySQL forensic_status with MongoDB (dry-run by default)."

    def add_arguments(self, parser):
        parser.add_argument('--tenant', help="Tenant id ('guest' or 'user:<id>')")
        parser.add_argument('--all-tenants', action='store_true', help='Process every active tenant + guest')
        parser.add_argument('--stale-minutes', type=int, default=None)
        parser.add_argument('--apply', action='store_true', help='Write changes (default: dry-run)')

    def _tenants(self, options):
        from User.models import UserDatabaseRegistry
        if options.get('tenant'):
            return [options['tenant']]
        if options.get('all_tenants'):
            ids = ['guest'] + [f"user:{r.user_id}" for r in
                               UserDatabaseRegistry.objects.using('default').filter(status='active').order_by('user_id')]
            return ids
        raise CommandError('Specify --tenant or --all-tenants')

    def handle(self, *args, **options):
        from django.conf import settings
        from User.models import Scan
        from User.security.tenancy import resolve_existing_tenant_alias
        from User.services.fallback_service import FallbackIntegrationService
        from User.services.nikhil.mongodb_repository import MongoDBRepository

        apply = options['apply']
        minutes = options['stale_minutes'] if options['stale_minutes'] is not None else settings.STALE_SCAN_MINUTES
        repo = MongoDBRepository()
        mode = 'APPLY' if apply else 'DRY-RUN'
        self.stdout.write(f"[{mode}] stale threshold={minutes} min, MongoDB available={repo.is_available()}")

        for tenant_id in self._tenants(options):
            alias = resolve_existing_tenant_alias(tenant_id)
            if alias is None:
                self.stdout.write(self.style.WARNING(f"{tenant_id}: no active tenant database; skipped"))
                continue
            cutoff = timezone.now() - timedelta(minutes=minutes)
            stale = Scan.objects.using(alias).filter(status__in=['UNCERTAIN', 'DEEP_ANALYSIS'], updated_at__lt=cutoff)
            stale_count = stale.count()
            if apply and stale_count:
                FallbackIntegrationService.recover_stale_scans(db=alias, older_than_minutes=minutes)

            stored = missing = unchanged = 0
            if repo.is_available():
                for scan in Scan.objects.using(alias).filter(forensic_status__in=['CACHE_ONLY', 'PENDING']):
                    if repo.exists(scan.id, tenant_id=tenant_id):
                        stored += 1
                        if apply:
                            Scan.objects.using(alias).filter(id=scan.id).update(forensic_status='STORED')
                    elif scan.forensic_status == 'CACHE_ONLY':
                        missing += 1
                        if apply:
                            Scan.objects.using(alias).filter(id=scan.id).update(forensic_status='MISSING')
                    else:
                        unchanged += 1
            self.stdout.write(
                f"{tenant_id} ({alias}): stale={stale_count} forensic->STORED={stored} "
                f"forensic->MISSING={missing} legacy-pending={unchanged}")
        if not apply:
            self.stdout.write("Dry-run only. Re-run with --apply to write changes.")
