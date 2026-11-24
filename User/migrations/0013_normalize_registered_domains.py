# Phase 1 data migration: registered-domain normalization of pari_domain.
#
# Legacy rows stored tldextract labels ("google") from user scans, or
# netloc-minus-www ("example.com") from the baseline import. The label form is
# ambiguous (google.com and google.co.in collapsed into one row), so names are
# NEVER guessed from the label. Instead, the registered domain is recovered from
# the URLs that reference each Domain row:
#
#   * all referencing URLs map to one registered domain R
#       - no row named R exists  -> rename this row in place (keeps every FK)
#       - a row named R exists   -> re-point the URLs to that row
#   * URLs map to several registered domains (an ambiguous, merged label)
#       -> split: URLs are re-pointed to the row for their own registered domain
#          (created if needed); the legacy row itself is kept.
#   * a row with no URLs cannot be verified and is left unchanged.
#
# No row is ever deleted; the migration is idempotent (a second run finds every
# URL already attached to the row of its own registered domain) and runs on
# guest / per-user tenant databases only (the router skips the core DB).

from collections import OrderedDict

from django.db import migrations


def normalize_domains(apps, schema_editor):
    from User.services.domain_normalization import normalize_url

    alias = schema_editor.connection.alias
    Domain = apps.get_model('User', 'Domain')
    URL = apps.get_model('User', 'URL')

    for dom in list(Domain.objects.using(alias).order_by('id')):
        urls = list(URL.objects.using(alias).filter(domain_id=dom.id).values_list('id', 'url'))
        if not urls:
            norm = normalize_url(dom.domain_name)
            if norm.suffix and norm.registered_domain == (dom.domain_name or '').lower() and not dom.tld:
                Domain.objects.using(alias).filter(id=dom.id).update(tld=norm.suffix[:63])
            continue

        groups = OrderedDict()
        suffixes = {}
        for url_id, url in urls:
            norm = normalize_url(url)
            reg = (norm.registered_domain or '')[:255]
            if not reg:
                continue
            groups.setdefault(reg, []).append(url_id)
            suffixes[reg] = norm.suffix[:63] if norm.suffix else None

        for reg, url_ids in groups.items():
            if reg == dom.domain_name:
                if suffixes.get(reg) and dom.tld != suffixes[reg]:
                    Domain.objects.using(alias).filter(id=dom.id).update(tld=suffixes[reg])
                continue
            target = Domain.objects.using(alias).filter(domain_name=reg).first()
            if target is None and len(groups) == 1:
                Domain.objects.using(alias).filter(id=dom.id).update(domain_name=reg, tld=suffixes.get(reg))
                continue
            if target is None:
                target = Domain.objects.using(alias).create(domain_name=reg, tld=suffixes.get(reg))
            URL.objects.using(alias).filter(id__in=url_ids).update(domain_id=target.id)


def mark_legacy_forensic_status(apps, schema_editor):
    """Pre-Phase-1 fallback evidence is unscoped in MongoDB -> needs reconciliation."""
    alias = schema_editor.connection.alias
    Scan = apps.get_model('User', 'Scan')
    Scan.objects.using(alias).filter(fallback_result__isnull=False, forensic_status='NOT_APPLICABLE') \
        .update(forensic_status='PENDING')


class Migration(migrations.Migration):

    dependencies = [
        ('User', '0012_phase1_tenant_integrity'),
    ]

    operations = [
        migrations.RunPython(normalize_domains, migrations.RunPython.noop),
        migrations.RunPython(mark_legacy_forensic_status, migrations.RunPython.noop),
    ]
