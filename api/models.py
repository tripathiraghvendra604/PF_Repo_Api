from __future__ import unicode_literals
from django.conf import settings
from django.db import models
from django.contrib.auth.models import User
# Create your models here.


def upload_location(instance, filename):
    return "%s/%s" %(instance.id, filename)


class UserInfo(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL)
    name = models.CharField(max_length=100)
    email = models.EmailField()
    phone = models.IntegerField()
    dob = models.DateField()
    height_field = models.IntegerField(default=0, null=True, blank=True)
    width_field = models.IntegerField(default=0, null=True, blank=True)
    profilePic = models.ImageField(upload_to=upload_location,
                                   blank=True, null=True,width_field='width_field',
                                 height_field='height_field')

    def __unicode__(self):
        return self.name


class EducationInfo(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL)
    year = models.TextField()
    degree = models.TextField()
    agreegate = models.TextField()

    def __unicode__(self):
        return self.year


class WorkExperience(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL)
    # internships
    from_intern = models.TextField(null=True, blank=True)
    to_intern = models.TextField(null=True, blank=True)
    company_intern = models.TextField(null=True, blank=True)
    title_intern = models.TextField(null=True, blank=True)
    status_intern = models.TextField(null=True, blank=True)

    #Jobs
    from_job = models.TextField(null=True, blank=True)
    to_job = models.TextField(null=True, blank=True)
    company_job = models.TextField(null=True, blank=True)
    title_job = models.TextField(null=True, blank=True)

    # Freelancer
    from_freelancer = models.TextField(null=True, blank=True)
    to_freelancer = models.TextField(null=True, blank=True)
    client_freelancer = models.TextField(null=True, blank=True)
    project_freelancer = models.TextField(null=True, blank=True)
    status_freelancer = models.TextField(null=True, blank=True)

    #Self
    from_self = models.TextField(null=True, blank=True)
    to_self = models.TextField(null=True, blank=True)
    project_self = models.TextField(null=True, blank=True)
    status_self = models.TextField(null=True, blank=True)

    def __unicode__(self):
        return self.title_intern

class Intrest(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL)
    intrest = models.TextField()

    def __unicode__(self):
        return self.intrest


class Skills(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL)
    technical = models.TextField(blank=True, null=True)
    soft = models.TextField(blank=True, null=True)
    other = models.TextField(blank=True, null=True)


class Certification(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL)

    #for online
    year_online = models.TextField(null=True, blank=True)
    agency_online = models.TextField(null=True, blank=True)
    detail_online = models.TextField(null=True, blank=True)
    #for offline
    year_offline = models.TextField(null=True, blank=True)
    agency_offline = models.TextField(null=True, blank=True)
    detail_offline = models.TextField(null=True, blank=True)
