# Generated by Django 5.1 on 2024-10-27 22:48

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('SecuraApp', '0012_alter_customuser_otp'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='socialmedia',
            name='adminSocialMedia',
        ),
        migrations.DeleteModel(
            name='AdminSocialMedia',
        ),
    ]