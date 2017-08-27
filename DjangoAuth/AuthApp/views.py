from django.contrib.auth import authenticate
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.status import HTTP_401_UNAUTHORIZED
from rest_framework.authtoken.models import Token
from django.contrib.auth.decorators import login_required
from django.shortcuts import render,redirect
from django.http import JsonResponse
from django.core import serializers
from django.contrib import auth
from rest_framework.authentication import TokenAuthentication, BasicAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from django.forms import ModelForm
from .models import Profile
from django.views.generic import View
from .serializers import UserToJson
from django.core.urlresolvers import reverse
from django.core.mail import EmailMessage
from django.contrib.auth.models import User
from rest_framework import generics
from .serializers import UserSignUpSerializer

class UserCreateView(generics.ListCreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSignUpSerializer

    def perform_create(self, serializer):
        serializer.save()

@login_required
def home(request):
    content = UserToJson(request.user)
    
    return JsonResponse(content, safe=False)


class Registration(View):
    authentication_classes = (TokenAuthentication, BasicAuthentication)
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        #The below if statement checks if the profile details are empty
        if len(str(request.user.profile.bio).strip()) > 0 :
            return redirect(reverse('home'))
        else:
            return render(request, 'registration.html', {"user":request.user}) 

    def post(self, request, *args, **kwargs):
        user = request.user
        user.profile.bio = request.POST.get('bio')
        user.profile.address = request.POST.get('address')
        user.profile.birth_date = request.POST.get('dob')
        user.save()
        return redirect(reverse('home'))


@api_view(["POST"])
def signup(request):
    
    try :
        user = User.objects.create_user(
                                username=request.data.get('username'),
                                email=request.POST.get('email'),
                                password=request.POST.get('password'),
                                first_name = request.POST.get('first_name'),
                                last_name = request.POST.get('last_name'),
                                )
    except Exception as e:
        return JsonResponse(str(e), safe=False)

    email = EmailMessage('subject', 'body of the message', 'noreply@bottlenose.co', ['vitor@freitas.com'])
    email.send()
    
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

def logout(request):
    auth.logout(request)
    return JsonResponse({"token": "dgdfh"})    

def check(request):
    #token, _ = Token.objects.get_or_create(user=user)
    return JsonResponse(request.user.email)