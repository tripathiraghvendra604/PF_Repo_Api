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
        return self.user.username


class EducationInfo(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL)
    year = models.TextField()
    degree = models.TextField()
    agreegate = models.TextField()
    institution = models.TextField()

    def __unicode__(self):
        return self.user.username


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
        return self.user.username


class Intrest(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL)
    intrest = models.TextField()

    def __unicode__(self):
        return self.user.username


class Skills(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL)
    technical = models.TextField(blank=True, null=True)
    soft = models.TextField(blank=True, null=True)
    other = models.TextField(blank=True, null=True)

    def __unicode__(self):
        return self.user.username


class Certification(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL)

    #for online and offline both
    year = models.TextField(null=True, blank=True)
    agency = models.TextField(null=True, blank=True)
    details = models.TextField(null=True, blank=True)
    mode = models.TextField(null=True, blank=True)

    def __unicode__(self):
        return self.user.username


class Publication(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL)

    # for national and international both
    year = models.TextField(null=True, blank=True)
    journal = models.TextField(null=True, blank=True)
    details = models.TextField(null=True, blank=True)
    status = models.TextField(null=True, blank=True)
    level = models.TextField()

    def __unicode__(self):
        return self.user.username


class Patent(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL)

    # for patents
    year = models.TextField(null=True, blank=True)
    details = models.TextField(null=True, blank=True)
    status = models.TextField(null=True, blank=True)
    patent_no = models.TextField(null=True, blank=True)

    def __unicode__(self):
        return self.user.username


class Books(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL)

    # for books
    year = models.TextField(null=True, blank=True)
    title = models.TextField(null=True, blank=True)
    publisher = models.TextField(null=True, blank=True)
    detail = models.TextField(null=True, blank=True)
    isbn = models.TextField(null=True, blank=True)
    links = models.TextField(null=True, blank=True)

    def __unicode__(self):
        return self.user.username


class Poster(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL)
    year = models.TextField(null=True, blank=True)
    title = models.TextField(null=True, blank=True)
    org = models.TextField(null=True, blank=True)
    detail = models.TextField(null=True, blank=True)
    link = models.TextField(null=True, blank=True)

    def __unicode__(self):
        return self.user.username


class Article(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL)
    year = models.TextField(null=True, blank=True)
    details = models.TextField(null=True, blank=True)
    publisher = models.TextField(null=True, blank=True)
    title = models.TextField(null=True, blank=True)
    links = models.TextField(null=True, blank=True)

    def __unicode__(self):
        return self.user.username


class Conference(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL)

    # for conferences and seminars
    year_c = models.TextField(null=True, blank=True)
    org_c = models.TextField(null=True, blank=True)
    detail_c = models.TextField(null=True, blank=True)
    status_c = models.TextField(null=True, blank=True)
    title_c = models.TextField(null=True, blank=True)

    # for invited talks/lectures
    year_i = models.TextField(null=True, blank=True)
    org_i = models.TextField(null=True, blank=True)
    detail_i = models.TextField(null=True, blank=True)
    status_i = models.TextField(null=True, blank=True)
    title_i = models.TextField(null=True, blank=True)

    def __unicode__(self):
        return self.user.username


class Achievement(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL)

    # for awards
    year_a = models.TextField(null=True, blank=True)
    org_a = models.TextField(null=True, blank=True)
    detail_a = models.TextField(null=True, blank=True)

    # for scholarships
    year_s = models.TextField(null=True, blank=True)
    org_s = models.TextField(null=True, blank=True)
    detail_s = models.TextField(null=True, blank=True)

    def __unicode__(self):
        return self.user.username


class Extracurricular(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL)

    # for extracurricular activities
    year_e = models.TextField(null=True, blank=True)
    org_e = models.TextField(null=True, blank=True)
    details_e = models.TextField(null=True, blank=True)

    # for volunteers activities
    year_v = models.TextField(null=True, blank=True)
    org_v = models.TextField(null=True, blank=True)
    details_v = models.TextField(null=True, blank=True)

    def __unicode__(self):
        return self.user.username


class SocialMediaLinks(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL)
    links = models.TextField()

    def __unicode__(self):
        return self.user.username