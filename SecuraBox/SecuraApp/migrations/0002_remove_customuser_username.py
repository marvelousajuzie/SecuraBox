# Generated by Django 5.1 on 2024-09-02 11:13

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('SecuraApp', '0001_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='customuser',
            name='username',
        ),
    ]
