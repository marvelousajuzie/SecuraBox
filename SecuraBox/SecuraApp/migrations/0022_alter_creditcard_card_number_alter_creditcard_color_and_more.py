# Generated by Django 5.1 on 2024-11-19 14:11

import django.core.validators
import encrypted_model_fields.fields
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('SecuraApp', '0021_alter_mail_password_alter_socialmedia_password'),
    ]

    operations = [
        migrations.AlterField(
            model_name='creditcard',
            name='card_number',
            field=encrypted_model_fields.fields.EncryptedCharField(validators=[django.core.validators.RegexValidator('^\\d{16}$', 'PIN must be a 16-digit number.')]),
        ),
        migrations.AlterField(
            model_name='creditcard',
            name='color',
            field=models.CharField(blank=True, help_text='Card color in hex format (e.g., #FF1100 for red).', max_length=50, null=True),
        ),
        migrations.AlterField(
            model_name='creditcard',
            name='expiration_date',
            field=models.CharField(blank=True, max_length=7, null=True, validators=[django.core.validators.RegexValidator(message='Enter a valid month and year in the format MM-YYYY', regex='^\\d{2}-\\d{4}$')]),
        ),
    ]
