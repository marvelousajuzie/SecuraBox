# Generated by Django 5.1 on 2024-10-20 20:48

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('SecuraApp', '0006_customuser_otp_customuser_otp_created_at'),
    ]

    operations = [
        migrations.AddField(
            model_name='customuser',
            name='otp_expires_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]