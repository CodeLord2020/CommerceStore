from django.core.mail import send_mail
from  django.conf import settings # EMAIL_HOST_USER ,CLIENT_URL
from django.contrib.auth.tokens import default_token_generator




def send_verification_mail(email, verify_link):
    subject = "Thestuff Email Verification"
    message = f"Please verify your account with this link: {verify_link}"
    email_from = settings.EMAIL_HOST
    send_mail(subject,message, email_from,[email],fail_silently=False)


def send_passwordchange_mail(email, reset_link):
    subject = "The stuff Password Change"
    message = f"Please change your account passwords with this link: {reset_link}"
    email_from = settings.EMAIL_HOST
    send_mail(subject,message, email_from,[email],fail_silently=False)
