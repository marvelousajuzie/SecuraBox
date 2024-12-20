# Generated by Django 5.1 on 2024-11-24 23:32

import encrypted_model_fields.fields
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('SecuraApp', '0004_alter_onlinebanking_password'),
    ]

    operations = [
        migrations.AlterField(
            model_name='onlinebanking',
            name='bankname',
            field=models.CharField(blank=True, max_length=250, null=True),
        ),
        migrations.AlterField(
            model_name='onlinebanking',
            name='password',
            field=encrypted_model_fields.fields.EncryptedCharField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='onlinebanking',
            name='username',
            field=models.CharField(blank=True, max_length=300, null=True),
        ),
    ]
