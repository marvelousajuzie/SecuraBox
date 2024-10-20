# Generated by Django 5.1 on 2024-09-02 11:04

import django.contrib.auth.password_validation
import django.core.validators
import django.db.models.deletion
import django.db.models.fields.related
import encrypted_model_fields.fields
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
    ]

    operations = [
        migrations.CreateModel(
            name='AdminMail',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('logo', models.ImageField(default='path/to/default/image.jpg', upload_to='mail_logos/')),
                ('mail_name', models.CharField(max_length=200)),
            ],
        ),
        migrations.CreateModel(
            name='AdminOnlineBank',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('logo', models.ImageField(default='path/to/default/image.jpg', upload_to='online_banklogos/')),
                ('bank_name', models.CharField(max_length=200)),
            ],
        ),
        migrations.CreateModel(
            name='AdminSocialMedia',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('logo', models.ImageField(default='path/to/default/image.jpg', upload_to='social_medialogos/')),
                ('platform_name', models.CharField(max_length=200)),
            ],
        ),
        migrations.CreateModel(
            name='Document',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=150)),
                ('description', models.TextField(blank=True, null=True)),
                ('file', models.FileField(upload_to='documents/')),
                ('updated_at', models.DateTimeField()),
            ],
        ),
        migrations.CreateModel(
            name='CustomUser',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('password', models.CharField(max_length=128, verbose_name='password')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('is_superuser', models.BooleanField(default=False, help_text='Designates that this user has all permissions without explicitly assigning them.', verbose_name='superuser status')),
                ('email', models.EmailField(max_length=254, unique=True, verbose_name='Email Address')),
                ('username', models.CharField(max_length=200, verbose_name='Username')),
                ('is_active', models.BooleanField(default=True)),
                ('is_staff', models.BooleanField(default=False)),
                ('date_joined', models.DateTimeField(auto_now_add=True)),
                ('groups', models.ManyToManyField(blank=True, help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.', related_name='user_set', related_query_name='user', to='auth.group', verbose_name='groups')),
                ('user_permissions', models.ManyToManyField(blank=True, help_text='Specific permissions for this user.', related_name='user_set', related_query_name='user', to='auth.permission', verbose_name='user permissions')),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='SocialMedia',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('email', models.CharField(blank=True, max_length=200, null=True)),
                ('phone_number', models.CharField(blank=True, max_length=11, null=True, validators=[django.core.validators.RegexValidator('^\\d{11}$', 'PIN must be a 11-digit number.')])),
                ('password', encrypted_model_fields.fields.EncryptedCharField(validators=[django.contrib.auth.password_validation.validate_password])),
                ('profile_url', models.URLField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('adminSocialMedia', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='SecuraApp.adminsocialmedia')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Pin',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('pin', encrypted_model_fields.fields.EncryptedCharField(validators=[django.core.validators.RegexValidator('^\\d{4}$', 'PIN must be a 4-digit number.')])),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='OnlineBanking',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('account_number', encrypted_model_fields.fields.EncryptedCharField()),
                ('phone_number', models.CharField(max_length=11, validators=[django.core.validators.RegexValidator('^\\d{11}$', 'PIN must be a 11-digit number.')])),
                ('password', encrypted_model_fields.fields.EncryptedCharField(default='', validators=[django.contrib.auth.password_validation.validate_password])),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('adminOnlineBank', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='SecuraApp.adminonlinebank')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Notes',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=100)),
                ('content', models.TextField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='NationalID',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('id_number', encrypted_model_fields.fields.EncryptedCharField(unique=True)),
                ('id_name', models.CharField(blank=True, max_length=100, null=True)),
                ('country', models.CharField(blank=True, max_length=100, null=True)),
                ('issue_date', models.DateField(blank=True, null=True)),
                ('expiration_date', models.DateField(blank=True, null=True)),
                ('document', models.FileField(blank=True, null=True, upload_to='certificates/')),
                ('user', models.ForeignKey(on_delete=django.db.models.fields.related.ForeignKey, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Mail',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('email', models.CharField(blank=True, max_length=200, null=True)),
                ('phone_number', models.CharField(blank=True, max_length=11, null=True, validators=[django.core.validators.RegexValidator('^\\d{11}$', 'PIN must be a 11-digit number.')])),
                ('password', encrypted_model_fields.fields.EncryptedCharField(default='', validators=[django.contrib.auth.password_validation.validate_password])),
                ('mail_url', models.URLField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('adminMail', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='SecuraApp.adminmail')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='DriversLicense',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('license_number', encrypted_model_fields.fields.EncryptedCharField(unique=True)),
                ('id_name', models.CharField(blank=True, max_length=100, null=True)),
                ('country', models.CharField(blank=True, max_length=100, null=True)),
                ('issue_date', models.DateField(blank=True, null=True)),
                ('expiration_date', models.DateField()),
                ('document', models.FileField(blank=True, null=True, upload_to='certificates/')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='CreditCard',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('bank_name', models.CharField(blank=True, max_length=150, null=True)),
                ('card_number', encrypted_model_fields.fields.EncryptedCharField(validators=[django.core.validators.RegexValidator('^\\d{16}$', 'PIN must be a 16-digit number.')])),
                ('cardholder_name', models.CharField(blank=True, max_length=150, null=True)),
                ('expiration_date', models.DateTimeField(blank=True, null=True)),
                ('cvv', encrypted_model_fields.fields.EncryptedCharField(blank=True, null=True, validators=[django.core.validators.RegexValidator('^\\d{3}$', 'PIN must be a 3-digit number.')])),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Country',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('country_name', models.CharField(max_length=200)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Certificates',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('issuing_Organization', models.CharField(max_length=300)),
                ('certificateID', encrypted_model_fields.fields.EncryptedCharField(unique=True)),
                ('certificate_name', models.CharField(max_length=200)),
                ('certificate_url', models.URLField(blank=True, null=True)),
                ('issue_date', models.DateField()),
                ('issued_by', models.CharField(blank=True, max_length=100, null=True)),
                ('document', models.FileField(blank=True, null=True, upload_to='certificates/')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
