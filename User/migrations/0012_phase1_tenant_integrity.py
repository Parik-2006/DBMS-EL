# Phase 1: tenant-scoped investigation identity, scan<->IP link, explicit
# forensic/failure state, exact history->scan link, wider public-suffix column,
# analyst permissions.
#
# investigation_id is added in three steps (nullable -> per-row backfill ->
# unique) so existing rows in every tenant database receive distinct UUIDs.

import uuid

import django.db.models.deletion
from django.db import migrations, models


def backfill_investigation_ids(apps, schema_editor):
    Scan = apps.get_model('User', 'Scan')
    alias = schema_editor.connection.alias
    for scan_id in Scan.objects.using(alias).filter(investigation_id__isnull=True).values_list('id', flat=True):
        Scan.objects.using(alias).filter(id=scan_id).update(investigation_id=uuid.uuid4())


class Migration(migrations.Migration):

    dependencies = [
        ('User', '0011_scanfinaldecision_and_more'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='analystreview',
            options={'permissions': [('submit_review', 'Can submit analyst reviews for scans'),
                                     ('override_final_decision', 'Can override authoritative (non-review) final decisions')]},
        ),
        migrations.AddField(
            model_name='maliciousbot',
            name='scan',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL,
                                    related_name='history_entries', to='User.scan'),
        ),
        migrations.AddField(
            model_name='scan',
            name='failure_reason',
            field=models.CharField(blank=True, default='', max_length=255),
        ),
        migrations.AddField(
            model_name='scan',
            name='forensic_status',
            field=models.CharField(choices=[('NOT_APPLICABLE', 'Not applicable (confident ML, no deep analysis)'),
                                            ('PENDING', 'Pending'), ('STORED', 'Stored durably in MongoDB'),
                                            ('CACHE_ONLY', 'Only in volatile in-process cache (not durable)'),
                                            ('FAILED', 'Storage failed'),
                                            ('MISSING', 'Expected evidence not found during reconciliation')],
                                   db_index=True, default='NOT_APPLICABLE', max_length=20),
        ),
        migrations.AddField(
            model_name='scan',
            name='investigation_id',
            field=models.UUIDField(editable=False, null=True),
        ),
        migrations.RunPython(backfill_investigation_ids, migrations.RunPython.noop),
        migrations.AlterField(
            model_name='scan',
            name='investigation_id',
            field=models.UUIDField(default=uuid.uuid4, editable=False, unique=True),
        ),
        migrations.AddField(
            model_name='scan',
            name='ip',
            field=models.ForeignKey(blank=True, help_text='Validated public IP observed by network analysis for this scan',
                                    null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='scans',
                                    to='User.ip'),
        ),
        migrations.AlterField(
            model_name='domain',
            name='tld',
            field=models.CharField(blank=True, help_text='Public suffix (e.g. com, co.in)', max_length=63, null=True),
        ),
        migrations.AlterField(
            model_name='scan',
            name='status',
            field=models.CharField(choices=[('CONFIDENT', 'Confident - ML prediction sufficient'),
                                            ('UNCERTAIN', 'Uncertain - routing to fallback'),
                                            ('DEEP_ANALYSIS', 'Deep analysis in progress'),
                                            ('COMPLETED', 'Completed - result stored'),
                                            ('FAILED', 'Failed - fallback analysis or persistence failed'),
                                            ('ERROR', 'Error during scan')],
                                   db_index=True, max_length=20),
        ),
    ]
