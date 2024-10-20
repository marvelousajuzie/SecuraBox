import secrets
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone, timedelta
from .models import CustomUser



OTP_EXPIRATION_MINUTES = 10

def send_otp_via_email(email):
    otp = str(secrets.randbelow(10000)).zfill(4) 
    subject = 'Your account verification email'
    message = f'Your OTP code is: {otp}. It will expire in {OTP_EXPIRATION_MINUTES} minutes.'
    email_from = settings.EMAIL_HOST_USER  

    try:
        user_obj = CustomUser.objects.get(email=email)
        
        expiration_time = timezone.now() + timedelta(minutes=OTP_EXPIRATION_MINUTES)
        send_mail(subject, message, email_from, [email])
        user_obj.otp = otp 
        user_obj.otp_created_at = timezone.now() 
        user_obj.otp_expires_at = expiration_time  
        user_obj.save()
    except CustomUser.DoesNotExist:
        print(f"User with email {email} does not exist.")
    except Exception as e:
        print(f"An error occurred: {e}")

