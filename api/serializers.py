from django.contrib.auth import update_session_auth_hash
from rest_framework import serializers
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from .models import (UserInfo, EducationInfo, WorkExperience, Intrest, Skills,
                     Certification, Publication, Patent, Books, Conference,
                     Achievement, Extracurricular, SocialMediaLinks)
from django.views.decorators.csrf import csrf_exempt
from rest_framework.response import Response


class UserSerializer(serializers.ModelSerializer):

    #password = serializers.CharField(write_only=True, required=False)
    #password2 = serializers.CharField(label='Confirm Password',write_only=True, required=False)
    '''email = serializers.EmailField(label='Email')
    class Meta:
        model = User
        fields = ('id', 'email', 'username', 'password')
        extra_kwargs = {
            "password" : {"write_only": True}
        }

    def validate(self, data):
            email = data['email']
            user_qs = User.objects.filter(email=email)
            if user_qs.exists():
                raise ValidationError('This User has already Registered')

            return data

        # def validate_password2(self, value):
        #     data = self.get_initial()
        #     password1 = data.get('password')
        #     password2 = value
        #     if password1 != password2:
        #         raise ValidationError("Passwords don't match")
        #     return value

    def create(self, **validated_data):
            return User.objects.create(**validated_data) '''
    class Meta:
        model = User
        fields = ('email', 'username', 'password')
        extra_kwargs = {
            "password": {"write_only": True}
        }

    def create(self, validated_data):
        print validated_data
        username = validated_data['username']
        email = validated_data['email']
        password = validated_data['password']
        u = User.objects.filter(email=email).distinct()
        if u.exists() or u.count() > 0:
            raise ValidationError('This Email is already registered!')


        else:
            user = User(username=username, email= email)
            user.set_password(password)
            user.save()

            return validated_data


class UserInfoSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserInfo
        fields = ('name', 'email', 'phone', 'dob', 'profilePic')

    '''def create(self, validated_data):
        name= validated_data['name']
        email = validated_data['email']
        phone = validated_data['phone']
        dob = validated_data['dob']
        profilePic = validated_data['profilePic']

        info = UserInfo(
            name= name,
            email= email,
            phone= phone,
            dob= dob,
            profilePic= profilePic
        )
        info.save()
        return self.data'''


class EducationInfoSerializer(serializers.ModelSerializer):
    class Meta:
        model = EducationInfo
        fields = ('year', 'degree', 'agreegate', 'user')


class WorkExperienceSerializer(serializers.ModelSerializer):
    class Meta:
        model = WorkExperience
        fields = ('from_intern', 'to_intern', 'company_intern', 'title_intern', 'status_intern',
                  'from_job', 'to_job', 'company_job', 'title_job',
                  'from_freelancer', 'to_freelancer', 'client_freelancer', 'project_freelancer',
                  'status_freelancer',
                  'from_self', 'to_self', 'project_self', 'status_self', 'user')


class SkillsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Skills
        fields = ('technical', 'soft', 'other', 'user')


class IntrestSerializer(serializers.ModelSerializer):
    class Meta:
        model = Intrest
        fields = ('intrest', 'user')


class CertificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Certification
        fields = ('year_online', 'agency_online', 'detail_online',
                  'year_offline', 'agency_offline', 'detail_offline', 'user')


class PublicationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Publication
        fields = ('year_national', 'journal_national', 'detail_national', 'status_national',
                  'year_international', 'journal_international', 'detail_international', 'status_international',
                  'user')


class PatentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Patent
        fields = ('year_patent', 'detail_patent', 'status_patent', 'patent_no',
                  'year_article', 'journel_article', 'detail_article', 'user')


class BooksSerializer(serializers.ModelSerializer):
    class Meta:
        model = Books
        fields = ('year_book', 'publisher_book', 'detail_book', 'isbn_book',
                  'year_poster', 'org_poster', 'detail_poster', 'user')


class ConferenceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Conference
        fields = ('year_c', 'org_c', 'detail_c', 'status_c',
                  'year_i', 'org_i', 'detail_i', 'status_i', 'user')


class AchievementSerializer(serializers.ModelSerializer):
    class Meta:
        model = Achievement
        fields = ('year_a', 'org_a', 'detail_a',
                  'year_s', 'org_s', 'detail_s', 'user')


class ExtraCurricularSerializer(serializers.ModelSerializer):
    class Meta:
        model = Extracurricular
        fields = ('year_e', 'org_e', 'details_e',
                  'year_v', 'org_v', 'details_v', 'user')


class SocialMediaLinksSerializer(serializers.ModelSerializer):
    class Meta:
        model = SocialMediaLinks
        fields = ('links', )


class CsrfSerializer(serializers.Serializer):
    csrf = serializers.CharField()


class UserLoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    email = serializers.EmailField()
    session_id = serializers.CharField()


class UserLogoutSerializer(serializers.Serializer):
    csrf = serializers.CharField()
    user = serializers.CharField()


class PasswordResetSerializer(serializers.Serializer):
    csrf = serializers.CharField()
    user = serializers.CharField()
    old_password = serializers.CharField()
    password1 = serializers.CharField()
    password2 = serializers.CharField()
