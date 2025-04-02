from django.db import models
from django.contrib.auth.models import User

# Create your models here.

class UserProfile(models.Model):
    USER_TYPE_CHOICES = [
        ('super_admin', 'Super Admin'),
        ('admin', 'Admin'),
        ('client', 'Client'),
    ]
    
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    user_type = models.CharField(max_length=20, choices=USER_TYPE_CHOICES, default='client')
    
    def __str__(self):
        return f"{self.user.username} - {self.get_user_type_display()}"

class Task(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('cancelled', 'Cancelled'),
        ('approved', 'Approved'),
    ]
    
    SERVICE_TYPE_CHOICES = [
        ('Full Service', 'Full Service'),
        ('TOP UP', 'TOP UP'),
    ]
    
    CLUSTER_CHOICES = [
        ('Hyderbad-1', 'Hyderbad-1'),
        ('Hyderbad-2', 'Hyderbad-2'),
        ('Kurnool', 'Kurnool'),
        ('Tirupathi', 'Tirupathi'),
        ('Warangal', 'Warangal'),
    ]
    
    # Basic fields
    title = models.CharField(max_length=200, null=True, blank=True)
    description = models.TextField(blank=True, null=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Task assignment fields
    global_id = models.CharField(max_length=100, null=True, blank=True)
    site_name = models.CharField(max_length=200, null=True, blank=True)
    cluster = models.CharField(max_length=50, choices=CLUSTER_CHOICES, null=True, blank=True)
    service_type = models.CharField(max_length=20, choices=SERVICE_TYPE_CHOICES, default='Full Service')
    date = models.DateField(null=True, blank=True)
    service_engineer = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='assigned_tasks',
        null=True,
        blank=True
    )
    assigned_to = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='client_tasks',
        null=True,
        blank=True
    )
    
    def __str__(self):
        if self.global_id and self.site_name:
            return f"{self.global_id} - {self.site_name}"
        return self.title or "Untitled Task"

class Report(models.Model):
    title = models.CharField(max_length=255)
    content = models.TextField()
    # New structured fields for technical report
    task_details = models.JSONField(null=True, blank=True)
    engine_details = models.JSONField(null=True, blank=True)
    alternator_details = models.JSONField(null=True, blank=True)
    dg_checkpoints = models.JSONField(null=True, blank=True)
    alternator_checkpoints = models.JSONField(null=True, blank=True)
    engine_checkpoints = models.JSONField(null=True, blank=True)
    general_checkpoints = models.JSONField(null=True, blank=True)
    conclusion = models.TextField(null=True, blank=True)
    # End of new fields
    submitted_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='reports')
    task = models.ForeignKey(Task, on_delete=models.CASCADE, related_name='reports', null=True, blank=True)
    attachment = models.FileField(upload_to='reports/', null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    STATUS_CHOICES = (
        ('pending', 'Pending'),
        ('in_progress', 'In Progress'),
        ('reviewed', 'Reviewed'),
        ('rejected', 'Rejected'),
    )
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    rejection_reason = models.TextField(blank=True, null=True)

    def __str__(self):
        return self.title
