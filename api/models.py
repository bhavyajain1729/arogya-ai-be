# api/models.py
from django.db import models
from django.contrib.auth.models import User

class MedicalReport(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    report_file = models.FileField(upload_to='reports/')
    extracted_text = models.TextField(blank=True)
    ai_description = models.TextField(blank=True)
    ai_medicine_rec = models.TextField(blank=True)
    ai_remedies = models.TextField(blank=True)
    ai_precautions = models.TextField(blank=True)
    emergency_video_url = models.URLField(max_length=500, blank=True)
    status = models.CharField(max_length=50, blank=True, default="Pending")
    
    # The duplicate line has been removed
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Report for {self.user.username} at {self.created_at.strftime('%Y-%m-%d %H:%M')}"
