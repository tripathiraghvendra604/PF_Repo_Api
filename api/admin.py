from django.contrib import admin

# Register your models here.
from .models import (UserInfo, EducationInfo, WorkExperience, Intrest, Skills, Certification, Publication,
                     Patent, Books, Conference, Achievement, Extracurricular, SocialMediaLinks, Poster,
                     Article)

admin.site.register(UserInfo)
admin.site.register(EducationInfo)
admin.site.register(WorkExperience)
admin.site.register(Intrest)
admin.site.register(Skills)
admin.site.register(Certification)
admin.site.register(Publication)
admin.site.register(Patent)
admin.site.register(Books)
admin.site.register(Conference)
admin.site.register(Achievement)
admin.site.register(Extracurricular)
admin.site.register(SocialMediaLinks)
admin.site.register(Poster)
admin.site.register(Article)