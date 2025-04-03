from rest_framework import serializers
from django.contrib.auth.models import User
from .models import Task, UserProfile, Report

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = ['user_type']

class UserSerializer(serializers.ModelSerializer):
    profile = UserProfileSerializer(required=True)
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'password', 'profile']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        profile_data = validated_data.pop('profile')
        password = validated_data.pop('password')
        user = User(**validated_data)
        user.set_password(password)
        user.save()
        UserProfile.objects.create(user=user, **profile_data)
        return user

class TaskSerializer(serializers.ModelSerializer):
    assigned_engineer = UserSerializer(read_only=True)
    report_status = serializers.SerializerMethodField()
    latest_report = serializers.SerializerMethodField()

    class Meta:
        model = Task
        fields = ['id', 'title', 'description', 'status', 'created_at', 'updated_at',
                 'global_id', 'site_name', 'cluster', 'service_type', 'date',
                 'service_engineer', 'assigned_to', 'assigned_engineer', 'report_status',
                 'latest_report']

    def get_report_status(self, obj):
        latest_report = obj.reports.order_by('-created_at').first()
        if latest_report:
            return latest_report.status
        return None

    def get_latest_report(self, obj):
        latest_report = obj.reports.order_by('-created_at').first()
        if latest_report:
            return {
                'id': latest_report.id,
                'status': latest_report.status,
                'rejection_reason': latest_report.rejection_reason,
                'created_at': latest_report.created_at
            }
        return None

class ReportSerializer(serializers.ModelSerializer):
    submitted_by_username = serializers.SerializerMethodField()
    submitted_on = serializers.SerializerMethodField()
    
    class Meta:
        model = Report
        fields = ['id', 'title', 'content', 'submitted_by', 'submitted_by_username', 
                  'task', 'attachment', 'created_at', 'updated_at', 'status', 'submitted_on', 
                  'rejection_reason', 'task_details', 'engine_details', 'alternator_details', 
                  'dg_checkpoints', 'alternator_checkpoints', 'engine_checkpoints', 
                  'general_checkpoints', 'conclusion']
        read_only_fields = ['submitted_by', 'created_at', 'updated_at']
        
    def get_submitted_by_username(self, obj):
        return obj.submitted_by.username if obj.submitted_by else None
        
    def get_submitted_on(self, obj):
        return obj.created_at.strftime('%Y-%m-%d') if obj.created_at else None 