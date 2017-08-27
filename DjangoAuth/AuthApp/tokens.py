from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils import six
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.models import User
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes, force_text
from django.core.mail import EmailMessage

class AccountActivationTokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        return (six.text_type(user.pk) + six.text_type(timestamp)) +  six.text_type(user.is_active)

account_activation_token = AccountActivationTokenGenerator()

def sendActivationMail(user):
    message = render_to_string('acc_active_email.html', {
                    'user':user, 
                    'domain':"localhost:8000",
                    'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                    'token': account_activation_token.make_token(user),
                })
    mail_subject = 'Activate your account.'
    print(message)
    to_email = user.email
    email = EmailMessage(mail_subject, message, to=[to_email])
    email.send() 