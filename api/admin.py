from django.contrib import admin
from .models import MedicalReport # Import our MedicalReport model

# Register your models here.

# This one line tells Django: "Show the MedicalReport model in the admin panel."
admin.site.register(MedicalReport)