from django.db import models
from django.contrib.auth.hashers import make_password, check_password
from django.conf import settings
import datetime
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.core.exceptions import ValidationError
from django.core.validators import MinLengthValidator, MaxLengthValidator
from encrypted_model_fields.fields import EncryptedCharField
from django.contrib.auth.password_validation import validate_password
from django.core.validators import RegexValidator
from django.utils import timezone
from django.utils.translation import gettext_lazy as _



class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(email, password, **extra_fields)



class CustomUser(AbstractBaseUser, PermissionsMixin):
    email= models.EmailField(unique= True, verbose_name= _('Email Address'))
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    date_joined = models.DateTimeField(auto_now_add=True)
    otp = models.CharField(max_length=4, blank=True, null=True,)
    otp_created_at = models.DateTimeField(blank=True, null=True)
    otp_expires_at = models.DateTimeField(blank=True, null=True)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.email




class Pin(models.Model):
    user = models.OneToOneField(CustomUser, on_delete= models.CASCADE)
    pin_hash = models.CharField(max_length=128,  null=False)
    

    pin_validator = RegexValidator(r'^\d{4}$', 'PIN must be a 4-digit number.')



    def set_pin(self, raw_pin):
        self.pin_validator(raw_pin)
        self.pin_hash = make_password(raw_pin, hasher='argon2')

    def verify_pin(self, raw_pin):
        return check_password(raw_pin, self.pin_hash)


    def __str__(self):
       return f'PIN for {self.user.email}'
    



class Country(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    country_name = models.CharField(max_length= 200)

    def __str__(self):
        return self.country_name
    



class SocialMedia(models.Model):
    PLATFORM_CHOICES = [
        ('facebook', 'Facebook'),
        ('instagram', 'Instagram'),
        ('tiktok', 'Tiktok'),
        ('telegram', 'Telegram'),
        ('linkdin', 'Linkdin'),
        ('x', 'X'),
        ('youtube', 'youtube'),
        ('behance', 'Behance'),
        ('snapchat', 'Snapchat'),
    ]
    user = models.ForeignKey(CustomUser, on_delete= models.CASCADE)
    platform = models.CharField(max_length=20, choices=PLATFORM_CHOICES, null=True, blank=True)
    email = models.CharField(max_length= 200, blank= True, null= True)
    phone_number = models.CharField(max_length=11, validators=[RegexValidator(r'^\d{11}$', 'PIN must be a 11-digit number.')], blank= True, null= True)
    password = EncryptedCharField(max_length=255, blank= True, null=True)
    profile_url = models.URLField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True) 
    updated_at = models.DateTimeField(auto_now=True)


    class Meta:
        ordering = ['-created_at'] 

    
    def __str__(self):
        return self.email or 'No Email'
    





class Mail(models.Model):
    PLATFORM_CHOICES = [
        ('email', 'Email'),
        ('yahoo', 'Yahoo'),
        ('apple email', 'Apple Email'),
        ('aol mail', 'Aol Mail'),
        ('outlook', 'Outlook'),
        ('zohoo', 'Zohoo'),
        ('proton mail', 'Proton Mail'),
        ('gmx', 'Gmx'),
    ]
    user = models.ForeignKey(CustomUser, on_delete= models.CASCADE)
    platform = models.CharField(max_length=20, choices=PLATFORM_CHOICES, null=True, blank=True)
    email = models.CharField(max_length= 200,  blank= True, null= True)
    phone_number = models.CharField(max_length=11, validators=[RegexValidator(r'^\d{11}$', 'PIN must be a 11-digit number.')], blank = True, null= True)
    password = EncryptedCharField(max_length=255, blank= True, null=True)
    mail_url = models.URLField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)  
    updated_at = models.DateTimeField(auto_now=True)


    class Meta:
        ordering = ['-created_at'] 

    
    def __str__(self):
        return self.email
    


# ADMIN USER
class AdminOnlineBank(models.Model):
    logo = models.ImageField(upload_to='online_banklogos/', default='path/to/default/image.jpg')
    bank_name = models.CharField(max_length= 200)


    def __str__(self):
        return self.bank




class OnlineBanking(models.Model):
    user = models.ForeignKey(CustomUser, on_delete= models.CASCADE)
    username = models.CharField(max_length= 300, blank= True, null = True)
    password = EncryptedCharField(max_length= 255, blank= True, null = True)
    bankname = models.CharField(max_length= 250, blank= True, null = True)
    created_at = models.DateTimeField(auto_now_add=True) 
    updated_at = models.DateTimeField(auto_now=True)


    class Meta:
        ordering = ['-created_at'] 
    
    def __str__(self):
        return self.username
    





class CreditCard(models.Model):
    user = models.ForeignKey(CustomUser, on_delete= models.CASCADE)
    card_number = EncryptedCharField(max_length=128, validators=[RegexValidator(r'^\d{16}$', 'PIN must be a 16-digit number.')])
    cardholder_name = models.CharField(max_length = 150, blank= True, null = True)
    expiration_date = models.CharField(max_length=7,  null=True, blank=True, validators=[ RegexValidator( regex=r'^\d{2}-\d{4}$', message='Enter a valid month and year in the format MM-YYYY' )])
    cvv = EncryptedCharField(max_length=3, validators=[RegexValidator(r'^\d{3}$', 'PIN must be a 3-digit number.')], blank= True, null = True)
    color = models.CharField( max_length=50,
        help_text="Card color in hex format (e.g., #FF1100 for red).", blank= True, null = True)
    created_at = models.DateTimeField(auto_now_add= True)
    updated_at = models.DateTimeField(auto_now= True)


    class Meta:
        ordering = ['-created_at'] 


    def __str__(self):
        return f"{self.cardholder_name} - **** **** **** {self.card_number[-4:]}"





class NationalID(models.Model):
    user = models.ForeignKey(CustomUser, on_delete= models.ForeignKey)
    id_number = EncryptedCharField(max_length=50, unique=True)
    id_name = models.CharField(max_length= 100, null= True, blank= True)
    country = models.CharField(max_length=100, null= True, blank= True)
    issue_date = models.DateField(null= True, blank= True)
    expiration_date = models.DateField(null=True, blank=True)
    document = models.FileField(upload_to='certificates/', blank=True, null=True)

    def ___str__(self):
        return f"{self.id_number} - {self.country}"
    auto_now_add=True



    


class Certificates(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    certificate_name = models.CharField(max_length= 200,  blank=True, null=True)
    certificate_document = models.FileField(upload_to='certificates/', null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add= True) 
    updated_at = models.DateTimeField(auto_now= True)


    class Meta:
        ordering = ['-created_at'] 

    def __str__(self):
        return self.certificate_name



class Notes(models.Model):
    user = models.ForeignKey(CustomUser, on_delete= models.CASCADE)
    title = models.CharField(max_length= 100)
    content = models.TextField(null= True, blank=True)
    created_at = models.DateTimeField(auto_now_add= True)
    updated_at = models.DateTimeField(auto_now= True)


    class Meta:
        ordering = ['-created_at'] 


    def __str__(self):
        return self.title


class Document(models.Model):
    user = models.ForeignKey(CustomUser, on_delete= models.CASCADE)
    title = models.CharField(max_length= 150, null= True, blank= True)
    description = models.TextField(null= True, blank= True)
    file = models.FileField(upload_to='documents/')
    created_at = models.DateTimeField(auto_now_add= True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at'] 

    def __str__(self):
        return self.title
    




class Notification(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name="notifications")
    message = models.TextField()
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.message