from rest_framework import serializers
from .models import Profile
from django.contrib.auth.models import User

class ProfileSerializer(serializers.ModelSerializer):
    """Serializer to map the Model instance into JSON format."""

    class Meta:
        """Meta class to map serializer's fields with the model fields."""
        model = Profile
        fields = ('bio','address','birth_date')
        
class UserSerializer(serializers.ModelSerializer):
    """Serializer to map the Model instance into JSON format."""
    profile = ProfileSerializer(many=False, read_only=True)

    class Meta:
        """Meta class to map serializer's fields with the model fields."""
        model = User
        fields = ('username','firstname','lastname','email','profile')

def UserToJson(user):
    content = {
        'username': str(user.username),  # `django.contrib.auth.User` instance.
        'firstname': str(user.first_name),  # None
        'lastname': str(user.last_name),
        'email': str(user.email),
        'bio': str(user.profile.bio),
        'address': str(user.profile.address),
        'birth_date': str(user.profile.birth_date),
    }
    return content