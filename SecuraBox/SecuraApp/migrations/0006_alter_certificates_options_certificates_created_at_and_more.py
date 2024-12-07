# Generated by Django 5.1 on 2024-12-04 07:23

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('SecuraApp', '0005_alter_onlinebanking_bankname_and_more'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='certificates',
            options={'ordering': ['-created_at']},
        ),
        migrations.AddField(
            model_name='certificates',
            name='created_at',
            field=models.DateTimeField(default=datetime.datetime(2024, 1, 1, 0, 0)),
        ),
        migrations.AddField(
            model_name='certificates',
            name='updated_at',
            field=models.DateTimeField(auto_now=True),
        ),
    ]
