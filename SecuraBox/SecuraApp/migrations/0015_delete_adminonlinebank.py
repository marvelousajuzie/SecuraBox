# Generated by Django 5.1 on 2025-01-01 20:41

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('SecuraApp', '0014_alter_certificates_certificate_document'),
    ]

    operations = [
        migrations.DeleteModel(
            name='AdminOnlineBank',
        ),
    ]