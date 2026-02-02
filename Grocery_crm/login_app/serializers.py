# login_app/serializers.py

from rest_framework import serializers
from .models import User,Message
from rest_framework.exceptions import ValidationError
from django.contrib.auth.hashers import check_password

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['email', 'userid', 'name', 'password', 'role', 'address']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)

    def update(self, instance, validated_data):
        password = validated_data.pop('password', None)
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        if password:
            instance.set_password(password)
        instance.save()
        return instance
    

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')

        try:
            # Check if the user exists
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise ValidationError({"email": "User with this email does not exist."})

        # Validate the password
        if not check_password(password, user.password):
            raise ValidationError({"password": "Invalid password."})

        # If validation passes, return the user data
        return {
            "email": user.email,
            "name": user.name,
            "role": user.role,
        } 

class MessageSerializer(serializers.ModelSerializer):
    class Meta:
        model = Message
        fields = ['id', 'from_user', 'to_user', 'message', 'session_id', 'created_date', 'is_read']