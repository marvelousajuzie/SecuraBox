# Generated by Django 5.1 on 2024-11-05 02:02

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('SecuraApp', '0016_remove_mail_adminmail_alter_mail_password_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='creditcard',
            name='bank_name',
        ),
        migrations.AlterField(
            model_name='creditcard',
            name='card_number',
            field=models.CharField(max_length=16, validators=[django.core.validators.RegexValidator('^\\d{16}$', 'PIN must be a 16-digit number.')]),
        ),
    ]
