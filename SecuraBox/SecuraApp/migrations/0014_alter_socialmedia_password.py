# Generated by Django 5.1 on 2024-10-28 22:21

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('SecuraApp', '0013_remove_socialmedia_adminsocialmedia_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='socialmedia',
            name='password',
            field=models.CharField(max_length=255),
        ),
    ]