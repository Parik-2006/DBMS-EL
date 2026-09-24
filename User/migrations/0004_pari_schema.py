# Generated migration for PARI schema
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('User', '0003_alter_maliciousbot_options_maliciousbot_confidence_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='Domain',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('domain_name', models.CharField(db_index=True, max_length=255, unique=True)),
                ('tld', models.CharField(blank=True, max_length=10, null=True)),
                ('status', models.CharField(choices=[('BENIGN', 'Benign'), ('SUSPICIOUS', 'Suspicious'), ('MALICIOUS', 'Malicious'), ('UNKNOWN', 'Unknown')], db_index=True, default='UNKNOWN', max_length=20)),
                ('risk_score', models.FloatField(default=0.0)),
                ('last_scanned', models.DateTimeField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'db_table': 'pari_domain',
            },
        ),
        migrations.CreateModel(
            name='IP',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ip_address', models.GenericIPAddressField(db_index=True, unique=True)),
                ('status', models.CharField(choices=[('BENIGN', 'Benign'), ('SUSPICIOUS', 'Suspicious'), ('MALICIOUS', 'Malicious'), ('UNKNOWN', 'Unknown')], db_index=True, default='UNKNOWN', max_length=20)),
                ('country', models.CharField(blank=True, max_length=100, null=True)),
                ('risk_score', models.FloatField(default=0.0)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'db_table': 'pari_ip',
                'verbose_name_plural': 'IPs',
            },
        ),
        migrations.CreateModel(
            name='ThreatIndicator',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('indicator_type', models.CharField(choices=[('IP_ADDRESS', 'IP Address'), ('DOMAIN', 'Domain'), ('URL_LENGTH', 'URL Length Anomaly'), ('SPECIAL_CHARS', 'Special Characters'), ('SHORTENER', 'URL Shortener'), ('SSL_CERTIFICATE', 'SSL Certificate Issue'), ('GEOLOCATION', 'Suspicious Geolocation'), ('REPUTATION', 'Low Reputation Score'), ('OTHER', 'Other')], db_index=True, max_length=30)),
                ('indicator_value', models.CharField(max_length=255)),
                ('severity', models.CharField(choices=[('LOW', 'Low'), ('MEDIUM', 'Medium'), ('HIGH', 'High'), ('CRITICAL', 'Critical')], default='MEDIUM', max_length=10)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
            options={
                'db_table': 'pari_threat_indicator',
                'unique_together': {('indicator_type', 'indicator_value')},
            },
        ),
        migrations.CreateModel(
            name='URL',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('url', models.CharField(db_index=True, max_length=500, unique=True)),
                ('source', models.CharField(choices=[('BASELINE', 'Baseline Dataset'), ('USER_SCAN', 'User Scan'), ('CORRELATION', 'Correlation Analysis')], default='USER_SCAN', max_length=20)),
                ('baseline_label', models.CharField(blank=True, choices=[('benign', 'Benign'), ('defacement', 'Defacement'), ('phishing', 'Phishing'), ('malware', 'Malware')], help_text='Only populated for baseline dataset URLs', max_length=20, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('domain', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='urls', to='User.domain')),
            ],
            options={
                'db_table': 'pari_url',
            },
        ),
        migrations.CreateModel(
            name='Scan',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('status', models.CharField(choices=[('CONFIDENT', 'Confident - ML prediction sufficient'), ('UNCERTAIN', 'Uncertain - routing to fallback'), ('DEEP_ANALYSIS', 'Deep analysis in progress'), ('COMPLETED', 'Completed - result stored'), ('ERROR', 'Error during scan')], db_index=True, max_length=20)),
                ('initial_model', models.CharField(default='RandomForest', help_text='ML model used for initial prediction', max_length=50)),
                ('fallback_model', models.CharField(blank=True, help_text='Fallback model if used', max_length=50, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True, db_index=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('completed_at', models.DateTimeField(blank=True, null=True)),
                ('url', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='scans', to='User.url')),
                ('user', models.ForeignKey(blank=True, db_constraint=False, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='scans', to='auth.user')),

            ],
            options={
                'db_table': 'pari_scan',
                'ordering': ['-created_at'],
            },
        ),
        migrations.CreateModel(
            name='ScanIndicator',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('detected_at', models.DateTimeField(auto_now_add=True)),
                ('indicator', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='User.threatindicator')),
                ('scan', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='threat_indicators', to='User.scan')),
            ],
            options={
                'db_table': 'pari_scan_indicator',
                'unique_together': {('scan', 'indicator')},
            },
        ),
        migrations.CreateModel(
            name='Prediction',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('model_name', models.CharField(max_length=50)),
                ('predicted_class', models.CharField(choices=[('Benign', 'Benign'), ('Phishing', 'Phishing'), ('Malware', 'Malware'), ('Defacement', 'Defacement'), ('Unknown', 'Unknown')], db_index=True, max_length=20)),
                ('confidence', models.FloatField(help_text='Confidence score 0.0-1.0')),
                ('risk_score', models.FloatField(help_text='Risk score 0.0-1.0')),
                ('probabilities', models.JSONField(blank=True, default=dict, help_text='Model output probabilities for each class', null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('scan', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='prediction', to='User.scan')),
            ],
            options={
                'db_table': 'pari_prediction',
            },
        ),
        migrations.AddIndex(
            model_name='domain',
            index=models.Index(fields=['domain_name'], name='pari_domain_domain_n_idx'),
        ),
        migrations.AddIndex(
            model_name='domain',
            index=models.Index(fields=['status'], name='pari_domain_status_idx'),
        ),
        migrations.AddIndex(
            model_name='domain',
            index=models.Index(fields=['risk_score'], name='pari_domain_risk_sco_idx'),
        ),
        migrations.AddIndex(
            model_name='ip',
            index=models.Index(fields=['ip_address'], name='pari_ip_ip_addres_idx'),
        ),
        migrations.AddIndex(
            model_name='ip',
            index=models.Index(fields=['status'], name='pari_ip_status_idx'),
        ),
        migrations.AddIndex(
            model_name='ip',
            index=models.Index(fields=['risk_score'], name='pari_ip_risk_score_idx'),
        ),
        migrations.AddIndex(
            model_name='threatindicator',
            index=models.Index(fields=['indicator_type'], name='pari_threat__indicat_idx'),
        ),
        migrations.AddIndex(
            model_name='threatindicator',
            index=models.Index(fields=['severity'], name='pari_threat__severity_idx'),
        ),
        migrations.AddIndex(
            model_name='url',
            index=models.Index(fields=['url'], name='pari_url_url_idx'),
        ),
        migrations.AddIndex(
            model_name='url',
            index=models.Index(fields=['source'], name='pari_url_source_idx'),
        ),
        migrations.AddIndex(
            model_name='url',
            index=models.Index(fields=['domain'], name='pari_url_domain_idx'),
        ),
        migrations.AddIndex(
            model_name='scan',
            index=models.Index(fields=['status'], name='pari_scan_status_idx'),
        ),
        migrations.AddIndex(
            model_name='scan',
            index=models.Index(fields=['user'], name='pari_scan_user_id_idx'),
        ),
        migrations.AddIndex(
            model_name='scan',
            index=models.Index(fields=['created_at'], name='pari_scan_created__idx'),
        ),
        migrations.AddIndex(
            model_name='scanindicator',
            index=models.Index(fields=['scan'], name='pari_scan__scan_id_idx'),
        ),
        migrations.AddIndex(
            model_name='scanindicator',
            index=models.Index(fields=['indicator'], name='pari_scan__indicat_idx'),
        ),
        migrations.AddIndex(
            model_name='prediction',
            index=models.Index(fields=['predicted_class'], name='pari_predict_predicte_idx'),
        ),
        migrations.AddIndex(
            model_name='prediction',
            index=models.Index(fields=['confidence'], name='pari_predict_confide_idx'),
        ),
        migrations.AddIndex(
            model_name='prediction',
            index=models.Index(fields=['risk_score'], name='pari_predict_risk_sco_idx'),
        ),
    ]
