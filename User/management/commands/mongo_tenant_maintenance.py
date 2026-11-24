"""
MongoDB tenant-isolation maintenance (Phase 1). Dry-run by default.

--create-indexes   Create the tenant-scoped unique indexes (INDEX_SPECS):
                   uq_tenant_scan {tenant_id, scan_id} and uq_investigation_id.
                   Both are partial indexes, so unscoped legacy documents never
                   conflict with them.
--audit-legacy     Classify pre-Phase-1 documents (no tenant_id):
                   * VERIFIABLE  - exactly one tenant has a scan with this scan_id
                                   whose pari_scan_fallback.mongo_document_reference
                                   equals the document _id (an independent link
                                   recorded by MySQL at write time) and whose URL
                                   matches the document URL.
                   * CONFLICT    - more than one tenant matches.
                   * UNVERIFIABLE- no tenant matches.
                   With --apply: VERIFIABLE documents get tenant_id/investigation_id
                   backfilled; CONFLICT documents are flagged quarantined=True.
                   UNVERIFIABLE documents are left untouched. Unscoped documents
                   are never returned by normal (tenant-filtered) retrieval.
Nothing is ever deleted.
"""

from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = "Create tenant indexes and audit/backfill/quarantine legacy MongoDB evidence (dry-run by default)."

    def add_arguments(self, parser):
        parser.add_argument('--create-indexes', action='store_true')
        parser.add_argument('--audit-legacy', action='store_true')
        parser.add_argument('--limit', type=int, default=1000)
        parser.add_argument('--apply', action='store_true', help='Perform writes (default: dry-run)')

    def handle(self, *args, **options):
        from User.services.nikhil.mongodb_repository import INDEX_SPECS, MongoDBRepository

        repo = MongoDBRepository()
        apply = options['apply']
        if not (options['create_indexes'] or options['audit_legacy']):
            raise CommandError('Specify --create-indexes and/or --audit-legacy')
        if not repo.is_available():
            raise CommandError('MongoDB is not available (MONGODB_URI unset or unreachable)')

        if options['create_indexes']:
            for spec in INDEX_SPECS:
                self.stdout.write(f"index {spec['name']}: keys={spec['keys']} unique={spec['unique']} "
                                  f"partial={spec['partialFilterExpression']}")
            if apply:
                names = repo.ensure_indexes()
                self.stdout.write(self.style.SUCCESS(f"created/verified indexes: {names}"))
            else:
                self.stdout.write("Dry-run: indexes not created. Re-run with --apply.")

        if options['audit_legacy']:
            self._audit(repo, options['limit'], apply)

    def _candidate_tenants(self):
        from User.models import UserDatabaseRegistry
        from User.security.tenancy import resolve_existing_tenant_alias
        tenants = []
        for tenant_id in ['guest'] + [f"user:{r.user_id}" for r in
                                      UserDatabaseRegistry.objects.using('default').filter(status='active')]:
            alias = resolve_existing_tenant_alias(tenant_id)
            if alias:
                tenants.append((tenant_id, alias))
        return tenants

    def _audit(self, repo, limit, apply):
        from User.models import Scan
        tenants = self._candidate_tenants()
        counts = {'VERIFIABLE': 0, 'CONFLICT': 0, 'UNVERIFIABLE': 0, 'BACKFILLED': 0, 'QUARANTINED': 0}
        for doc in repo.iter_legacy_documents(limit=limit):
            doc_id = doc['_id']
            scan_id = doc.get('scan_id')
            try:
                scan_id = int(scan_id)
            except (TypeError, ValueError):
                counts['UNVERIFIABLE'] += 1
                continue
            matches = []
            for tenant_id, alias in tenants:
                scan = (Scan.objects.using(alias).select_related('url')
                        .filter(id=scan_id, fallback_result__mongo_document_reference=str(doc_id)).first())
                if scan and (not doc.get('url') or scan.url.url == doc.get('url')):
                    matches.append((tenant_id, scan))
            if len(matches) == 1:
                counts['VERIFIABLE'] += 1
                tenant_id, scan = matches[0]
                self.stdout.write(f"VERIFIABLE {doc_id} scan_id={scan_id} -> {tenant_id}")
                if apply and repo.backfill_legacy_owner(doc_id, tenant_id, scan.investigation_id):
                    counts['BACKFILLED'] += 1
            elif len(matches) > 1:
                counts['CONFLICT'] += 1
                owners = ', '.join(t for t, _ in matches)
                self.stdout.write(self.style.WARNING(f"CONFLICT {doc_id} scan_id={scan_id} claimed by {owners}"))
                if apply and repo.quarantine_legacy_document(doc_id, f"ownership conflict: {owners}"):
                    counts['QUARANTINED'] += 1
            else:
                counts['UNVERIFIABLE'] += 1
        self.stdout.write(str(counts))
        if not apply:
            self.stdout.write("Dry-run only. Re-run with --apply to backfill/quarantine.")
