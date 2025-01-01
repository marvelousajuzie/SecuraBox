import secrets
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
from .models import CustomUser



# OTP_EXPIRATION_MINUTES = 10

# def send_otp_via_emails(email):
#     otp = str(secrets.randbelow(10000)).zfill(4) 
#     subject = 'Your account verification email'
#     message = f'Your OTP code is: {otp}. It will expire in {OTP_EXPIRATION_MINUTES} minutes.'
#     email_from = settings.EMAIL_HOST_USER  

#     try:
#         user_obj = CustomUser.objects.get(email=email)
        
#         expiration_time = timezone.now() + timedelta(minutes=OTP_EXPIRATION_MINUTES)
#         send_mail(subject, message, email_from, [email])
#         user_obj.otp = otp 
#         user_obj.otp_created_at = timezone.now() 
#         user_obj.otp_expires_at = expiration_time  
#         user_obj.save()
#     except CustomUser.DoesNotExist:
#         print(f"User with email {email} does not exist.")
#     except Exception as e:
#         print(f"An error occurred: {e}")






# OTP_EXPIRATION_MINUTES = 10

# def send_otp_via_email(email, otp):
#     """Send an OTP to the provided email."""
#     subject = 'Your account verification email'
#     message = f'Your OTP code is: {otp}. It will expire in {OTP_EXPIRATION_MINUTES} minutes.'
#     email_from = settings.EMAIL_HOST_USER

#     try:
#         send_mail(subject, message, email_from, [email])
#     except Exception as e:
#         raise RuntimeError(f"Failed to send OTP email: {e}")




OTP_EXPIRATION_MINUTES = 10

def generate_otp(length=4):
    """Generate a numeric OTP of specified length."""
    return ''.join(secrets.choice('0123456789') for _ in range(length))

def send_otp_via_email(email, otp):
    """
    Send an OTP to the provided email.
    
    :param email: The user's email address.
    :param otp: The generated OTP.
    """
    subject = 'Your account verification email'
    message = f'Your OTP code is: {otp}. It will expire in {OTP_EXPIRATION_MINUTES} minutes.'
    email_from = settings.EMAIL_HOST_USER

    try:
        send_mail(subject, message, email_from, [email])
    except Exception as e:
        raise RuntimeError(f"Failed to send OTP email: {e}")
