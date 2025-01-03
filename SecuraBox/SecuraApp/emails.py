import secrets
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
from .models import CustomUser





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
        return True, "Email sent successfully."
    except Exception as e:
        return False, str(e)
