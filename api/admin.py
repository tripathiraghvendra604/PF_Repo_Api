from django.contrib import admin

# Register your models here.
from .models import UserInfo, EducationInfo, WorkExperience, Intrest, Skills

admin.site.register(UserInfo)
admin.site.register(EducationInfo)
admin.site.register(WorkExperience)
admin.site.register(Intrest)
admin.site.register(Skills)