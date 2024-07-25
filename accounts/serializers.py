from rest_framework import serializers
from .models import User
from .serializers import *
import re
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError


class UserRegisterSerilaizer(serializers.ModelSerializer):
    password2 = serializers.CharField(style={'input_type': 'password'}, write_only= True)

    class Meta:
        model = User
        fields = ['email', 'first_name', 'last_name', 'password', 'password2']

        extra_kwargs ={
            'password':{'write_only': True}
        }

    def validate(self, attrs):
        password = attrs.get('password','')
        password2 = attrs.get('password2','')


        if password != password2:
            raise serializers.ValidationError(
                {
                    'error': 'passwords does not match'
                }
            )
        return attrs
    
    def create(self, validated_data):
        user = User.objects.create_user(
            email = validated_data['email'],
            first_name = validated_data.get('first_name'),
            last_name = validated_data.get('last_name'),
            password = validated_data.get('password'),
        )
    
        return user



class AdminRegisterSerializer(serializers.ModelSerializer):
    '''
    Admin registration serializer.
    '''
    password1 = serializers.CharField(
        max_length=100, 
        required=True, 
        write_only=True,
    )
    password2 = serializers.CharField(
        max_length=100, 
        required=True,
        write_only=True,
    )
    class Meta:
        model = User
        fields = (
            'email',
            'password1',
            'password2',
            'first_name',
            'last_name',
        )
    
    def validate(self, data):
        password = data.get('password1')
        confirm_password = data.get('password2')
        errors = dict()

        if password != confirm_password:
            errors['password'] =  "Password mismatch!"
        
        if errors:
            raise serializers.ValidationError(errors)
        return super(AdminRegisterSerializer, self).validate(data)
    
    def create(self, validated_data):
        admin = User.objects.create_superuser(
            email=validated_data['email'].lower(),
            password=validated_data['password1'],
            first_name=validated_data.get('first_name', ''),
            last_name=validated_data.get('last_name', '')
        )
        return admin



class VerifyTokenSerializer(serializers.Serializer):
    """Serializer for token verification"""
    token = serializers.CharField(required=True)



class LoginUserSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True)


class UserDetailSerilaizer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['email', 'first_name', 'last_name', 'is_verified','is_staff', 'is_active']   


class UserCompleteInfoSerilaizer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'


class LogoutUserSerializer(serializers.Serializer):
    refresh_token = serializers.CharField()

    default_error_message = {
        'bad_token':('Token is Invalid or has expired')
    }

    def validate(self, attrs):
        self.token = attrs.get('refresh_token')
        return attrs
    
    def save(self, **kwargs):

        try:
            token = RefreshToken(self.token)
            token.blacklist()

        except TokenError:
            return self.fail('bad token')


class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

    def validate_email(self, value):
        if not re.match(r"[^@]+@[^@]+\.[^@]+", value):
            raise serializers.ValidationError("Please enter a valid email address.")

        print(value)
        return value 

class PasswordResetConfirmSerializer(serializers.Serializer):
    """serializer to reset password"""

    token = serializers.CharField(required=True)
    new_password = serializers.CharField(write_only=True)





class UserCompleteInfo(serializers.ModelSerializer):
    '''User serializer which is only available to only `Admin` usertype'''
    class Meta:
        model = User
        fields = (
            'id',
            'email',
            'first_name',
            'last_name',
            'is_superuser',
            'is_staff',
            'is_active',
            'created_at',
            'last_login',
        )
