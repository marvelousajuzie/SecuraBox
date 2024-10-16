from django.core.mail import send_mail
import random
from django.conf import settings
from SecuraApp.models.v1_models import CustomUser





def send_otp_via_email(email):
    otp = str(random.randint(1000, 9999))  
    subject = 'Your account verification email'
    message = f'Your OTP code is: {otp}'
    email_from = settings.EMAIL_HOST_USER  
    send_mail(subject, message, email_from, [email])
    try:
        user_obj = CustomUser.objects.get(email=email)
        user_obj.otp = otp  
        user_obj.save() 
    except CustomUser.DoesNotExist:
        print(f"User with email {email} does not exist.")
