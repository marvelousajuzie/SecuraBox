from django.db import models
from django.contrib.auth.hashers import make_password, check_password
from django.conf import settings
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.core.exceptions import ValidationError
from django.core.validators import MinLengthValidator, MaxLengthValidator
from encrypted_model_fields.fields import EncryptedCharField
from django.contrib.auth.password_validation import validate_password
from django.core.validators import RegexValidator
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
    user = models.ForeignKey(CustomUser, on_delete= models.CASCADE)
    email = models.CharField(max_length= 200, blank= True, null= True)
    phone_number = models.CharField(max_length=11, validators=[RegexValidator(r'^\d{11}$', 'PIN must be a 11-digit number.')], blank= True, null= True)
    password = models.CharField(max_length=255, blank= True, null=True)
    profile_url = models.URLField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True) 
    updated_at = models.DateTimeField(auto_now=True)


    def set_password(self, raw_password):
        self.password = make_password(raw_password, hasher='argon2')
        self.save(update_fields=["password"])

    
    def __str__(self):
        return self.email or 'No Email'
    





class Mail(models.Model):
    user = models.ForeignKey(CustomUser, on_delete= models.CASCADE)
    email = models.CharField(max_length= 200,  blank= True, null= True)
    phone_number = models.CharField(max_length=11, validators=[RegexValidator(r'^\d{11}$', 'PIN must be a 11-digit number.')], blank = True, null= True)
    password = models.CharField(max_length=255, blank= True, null=True)
    mail_url = models.URLField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)  
    updated_at = models.DateTimeField(auto_now=True)


    
    def set_password(self, raw_password):
        self.password = make_password(raw_password, hasher='argon2')
        self.save(update_fields=["password"])

    
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
    adminOnlineBank = models.ForeignKey(AdminOnlineBank, on_delete= models.CASCADE,  blank = True, null= True)
    account_number = EncryptedCharField(max_length= 50)
    phone_number = models.CharField(max_length=11, validators=[RegexValidator(r'^\d{11}$', 'PIN must be a 11-digit number.')])
    password = EncryptedCharField(max_length= 255, validators=[validate_password], default= '')
    created_at = models.DateTimeField(auto_now_add=True) 
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.account_number
    





class CreditCard(models.Model):
    user = models.ForeignKey(CustomUser, on_delete= models.CASCADE)
    card_number = models.CharField(max_length=128, validators=[RegexValidator(r'^\d{16}$', 'PIN must be a 16-digit number.')])
    cardholder_name = models.CharField(max_length = 150, blank= True, null = True)
    expiration_date = models.DateTimeField(null= True, blank= True)
    cvv = EncryptedCharField(max_length=3, validators=[RegexValidator(r'^\d{3}$', 'PIN must be a 3-digit number.')], blank= True, null = True)
    color = models.CharField(
        max_length=7, 
        default='#FF1100', 
        validators=[RegexValidator(r'^#([A-Fa-f0-9]{6})$', 'Color must be a valid hex code.')],
        help_text="Card color in hex format (e.g., #FF1100 for red).")
    created_at = models.DateTimeField(auto_now_add= True)
    updated_at = models.DateTimeField(auto_now= True)


    
    def set_card_number(self, raw_card_number):
        self.card_number = make_password(raw_card_number, hasher='argon2')
        self.save(update_fields=["card_number"])

    def set_cvv(self, raw_cvv):
        self.cvv = make_password(raw_cvv, hasher = 'argon2')
        self.save(update_fields=["cvv"])



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


class DriversLicense(models.Model):
    user = models.ForeignKey(CustomUser, on_delete= models.CASCADE)
    license_number = EncryptedCharField(max_length=50, unique=True)
    id_name = models.CharField(max_length= 100, blank= True, null= True)
    country = models.CharField(max_length=100, blank= True, null= True)
    issue_date = models.DateField(null= True, blank= True)
    expiration_date = models.DateField(null= True, blank= True)
    document = models.FileField(upload_to='certificates/', blank=True, null=True)

    def __str__(self):
        return f"{self.license_number} - {self.country}"
    


class Certificates(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    certificate_name = models.CharField(max_length= 200,  blank=True, null=True)
    certificate_document = models.FileField(upload_to='certificates/',  blank=True, null=True)


    def __str__(self):
        return self.certificate_name



class Notes(models.Model):
    user = models.ForeignKey(CustomUser, on_delete= models.CASCADE)
    title = models.CharField(max_length= 100)
    content = models.TextField(null= True, blank=True)
    created_at = models.DateTimeField(auto_now_add= True)
    updated_at = models.DateTimeField(auto_now= True)


    def __str__(self):
        return self.title


class Document(models.Model):
    title = models.CharField(max_length= 150, null= True, blank= True)
    description = models.TextField(null= True, blank= True)
    file = models.FileField(upload_to='documents/')
    updated_at = models.DateTimeField()


    def __str__(self):
        return self.title