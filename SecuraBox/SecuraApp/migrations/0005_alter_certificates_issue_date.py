# Generated by Django 5.1 on 2024-09-02 12:29

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('SecuraApp', '0004_alter_driverslicense_expiration_date'),
    ]

    operations = [
        migrations.AlterField(
            model_name='certificates',
            name='issue_date',
            field=models.DateField(blank=True, null=True),
        ),
    ]