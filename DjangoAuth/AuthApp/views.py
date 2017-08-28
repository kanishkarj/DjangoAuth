from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required

from rest_framework import generics
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.status import HTTP_401_UNAUTHORIZED
from rest_framework.authtoken.models import Token
from rest_framework.authentication import TokenAuthentication, BasicAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView

from django.shortcuts import render,redirect
from django.http import JsonResponse, HttpResponse
from django.core import serializers
from django.core.urlresolvers import reverse
from django.contrib import auth
from django.forms import ModelForm
from django.views.generic import View
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_text

from .models import Profile
from .serializers import UserSignUpSerializer,UserToJson
from .tokens import account_activation_token, sendActivationMail

@login_required
def home(request):
    ''' if request.user.is_active == False :
            sendActivationMail(request.user)
            return HttpResponse('Please verify your email address before you proceed')
    '''
    content = UserToJson(request.user)
    return JsonResponse(content, safe=False)

def activate(request, uidb64, token):
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.save()        
        # return redirect('home')
        return HttpResponse('Thank you for your email confirmation. Now you can login your account.')
    else:
        return HttpResponse('Activation link is invalid!')


@api_view(["POST"])
def temp(request):
    '''   
    username = request.data.get("username")
    password = request.data.get("password")

    user = authenticate(username=username, password=password)
    if not user:
        return Response({"error": "Login failed"}, status=HTTP_401_UNAUTHORIZED)
    '''
    token, _ = Token.objects.get_or_create(user=request.user)
    return Response({"token": token.key})
 
@api_view(["POST"])
def registerPost(self, request, *args, **kwargs):
        user = request.user
        user.profile.bio = request.POST.get('bio')
        user.profile.address = request.POST.get('address')
        user.profile.birth_date = request.POST.get('dob')
        user.save()
        return redirect(reverse('home'))

@api_view(["POST"])
def update(request):
    user = request.user
    if 'first_name' in request.POST:
        user.first_name = request.POST.get('first_name')
    if 'last_name' in request.POST:
        user.last_name = request.POST.get('last_name')
    if 'email' in request.POST:
        user.email = request.POST.get('email')
    if 'bio' in request.POST:
        user.profile.bio = request.POST.get('bio')
    if 'address' in request.POST:
        user.profile.address = request.POST.get('address')
    if 'dob' in request.POST:
        user.profile.birth_date = request.POST.get('dob')
    user.save()
    
    return JsonResponse(user.username, safe=False)



@api_view(["POST"])
def signup(request):
    try :
        user = User.objects.create_user(
                                username=request.data.get('username'),
                                email=request.POST.get('email'),
                                password=request.POST.get('password'),
                                first_name = request.POST.get('first_name'),
                                last_name = request.POST.get('last_name'),
                                is_active=False
                                )
        sendActivationMail(user)
    except Exception as e:
        return JsonResponse(str(e), safe=False)

    content = UserToJson(user)
    return JsonResponse(content, safe=False)

@api_view(["POST"])
def login(request):
    username = request.data.get("username")
    password = request.data.get("password")

    user = authenticate(username=username, password=password)
    if not user:
        return Response({"error": "Login failed"}, status=HTTP_401_UNAUTHORIZED)

    token, _ = Token.objects.get_or_create(user=user)
    return Response({"token": token.key})


class LogOut(View):
    authentication_classes = (TokenAuthentication, BasicAuthentication)
    permission_classes = (IsAuthenticated,)
    
    def get(self, request, *args, **kwargs):
        Token.objects.filter(user_id=request.user.id).delete()
        auth.logout(request)
        return JsonResponse({"token": "dgdfh"})

def check(request):
    #token, _ = Token.objects.get_or_create(user=user)
    return JsonResponse(request.user.email)