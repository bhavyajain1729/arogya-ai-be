# api/serializers.py
from rest_framework import serializers
from django.contrib.auth.models import User
from .models import MedicalReport

class MedicalReportSerializer(serializers.ModelSerializer):
    class Meta:
        model = MedicalReport
        fields = [
            'id', 'user', 'report_file', 'created_at',
            'ai_description', 'ai_medicine_rec', 'ai_remedies', 'ai_precautions',
            'emergency_video_url', 'status'
        ]

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('username', 'email', 'password')
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password']
        )
        return user