from django.shortcuts import render, get_object_or_404
from rest_framework import permissions, viewsets, status, views
from .models import (User, UserInfo, EducationInfo, WorkExperience, Intrest,
                     Skills, Certification, Publication, Patent, Books,
                     Conference, Achievement, Extracurricular, SocialMediaLinks)
from .permissions import IsAccountOwner
from .serializers import (UserSerializer,
                          UserInfoSerializer,
                          EducationInfoSerializer,
                          CsrfSerializer,
                          UserLoginSerializer,
                          WorkExperienceSerializer,
                          IntrestSerializer,
                          SkillsSerializer,
                          CertificationSerializer,
                          PublicationSerializer,
                          PatentSerializer,
                          BooksSerializer,
                          ConferenceSerializer,
                          AchievementSerializer, UserLogoutSerializer, PasswordResetSerializer,
                          ExtraCurricularSerializer, SocialMediaLinksSerializer)


from rest_framework.response import Response
from rest_framework.generics import CreateAPIView
from django.middleware import csrf
from django.contrib.auth import authenticate, login, logout
from django.contrib.sessions.models import Session


class UserViewSet(CreateAPIView):
    lookup_field = 'username'
    queryset = User.objects.all()
    serializer_class = UserSerializer

    '''def get_permissions(self):
        if self.request.method in permissions.SAFE_METHODS:
            return (permissions.AllowAny(),)
        if self.request.method == 'POST':
            return (permissions.AllowAny(),)
        return (permissions.IsAuthenticated(), IsAccountOwner(),)'''

    # for CSRF Token
    def get_or_create_csrf_token(self, request):
        token = request.META.get('CSRF_COOKIE', None)
        if token is None:
            token = csrf._get_new_csrf_key()
            request.META['CSRF_COOKIE'] = token
        request.META['CSRF_COOKIE_USED'] = True
        return token

    def get(self, request, *args, **kwargs):
        serializer_class = CsrfSerializer
        csrf = self.get_or_create_csrf_token(request)
        csrf = csrf.decode('unicode-escape')
        print csrf
        return Response({
            'csrf': csrf,

        })

    def create(self, request):
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():

            email = request.data.get('email', None)
            u = User.objects.filter(email=email).distinct()
            if u.exists() or u.count() > 0:
                return Response({
                    'status': 'Bad Request',
                    'message': 'This email is already registered!'
                })

            else:
                User.objects.create_user(**serializer.validated_data)

                return Response({
                    'status': 'Account Created',
                    'message': 'User Registered'
                })

        return Response({
            'status': 'Bad request',
            'message': 'Account could not be created with received data.'
        }, status=status.HTTP_400_BAD_REQUEST)


class LoginView(views.APIView):
    def get_or_create_csrf_token(self, request):
        token = request.META.get('CSRF_COOKIE', None)
        if token is None:
            token = csrf._get_new_csrf_key()
            request.META['CSRF_COOKIE'] = token
        request.META['CSRF_COOKIE_USED'] = True
        return token

    def get(self, request, *args, **kwargs):
        serializer_class = CsrfSerializer
        csrf = self.get_or_create_csrf_token(request)
        csrf = csrf.decode('unicode-escape')
        return Response({
            'csrf': csrf,

        })

    def post(self, request, format= None):
        data = request.data
        #print data
        username = data.get('username')
        password = data.get('password')
        account = authenticate(username=username, password=password)
        if account is not None:
            login(request, account)
            #serialized = UserSerializer(account)
            '''serialized = UserLoginSerializer(account)
            serialized.data['session_id'] = self.request.session._session_key.decode('unicode-escape')
            print self.request.session._session_key
            return Response(serialized.data) '''
            return Response({
                "username": username.decode('unicode-escape'),
                "session_id": self.request.session._session_key.decode('unicode-escape')
            })

        else:
            return Response({
                'status': 'Unauthorized',
                'message': 'Username/password combination invalid.'
            }, status=status.HTTP_401_UNAUTHORIZED)


class LogoutView(views.APIView):
    permission_classes = (permissions.IsAuthenticated, )
    serializer_class = UserLogoutSerializer
    print 'logout url'

    def get_or_create_csrf_token(self, request):
        token = request.META.get('CSRF_COOKIE', None)
        if token is None:
            token = csrf._get_new_csrf_key()
            request.META['CSRF_COOKIE'] = token
        request.META['CSRF_COOKIE_USED'] = True
        return token

    def get(self, request, *args, **kwargs):
        serializer_class = CsrfSerializer
        csrf = self.get_or_create_csrf_token(request)
        csrf = csrf.decode('unicode-escape')
        print csrf
        return Response({
            'csrf': csrf,

        })

    def post(self, request, *args, **kwargs):
        data_dict = request.data
        exist_user = data_dict['user']
        user = User.objects.get(username=exist_user)
        [s.delete() for s in Session.objects.all() if str(s.get_decoded().get('_auth_user_id')) == str(user.id)]
        return Response({'message': 'Logged Out!'}, status=status.HTTP_200_OK)


class PasswordResetView(views.APIView):
    queryset = User.objects.all()
    serializer_class = PasswordResetSerializer

    def get_or_create_csrf_token(self, request):
        token = request.META.get('CSRF_COOKIE', None)
        if token is None:
            token = csrf._get_new_csrf_key()
            request.META['CSRF_COOKIE'] = token
        request.META['CSRF_COOKIE_USED'] = True
        return token

    def get(self, request, *args, **kwargs):
        serializer_class = CsrfSerializer
        csrf = self.get_or_create_csrf_token(request)
        csrf = csrf.decode('unicode-escape')
        print csrf
        return Response({
            'csrf': csrf,

        })

    def post(self, request, *args, **kwargs):
        data_dict = request.data
        exist_user = data_dict['user']
        old_password = data_dict['old_password']
        password1 = data_dict['password1']
        password2 = data_dict['password2']
        user = User.objects.get(username=exist_user)

        auth_user = authenticate(username= user.username, password=old_password)
        if auth_user is not None:
            if password1 == password2:
                auth_user.set_password(password1)
                auth_user.save()
                return Response({'message': "Password Successfully Reset"})


class UserInfoAPIView(CreateAPIView):
    queryset = UserInfo.objects.all()
    serializer_class = UserInfoSerializer


    def get_or_create_csrf_token(self, request):
        token = request.META.get('CSRF_COOKIE', None)
        if token is None:
            token = csrf._get_new_csrf_key()
            request.META['CSRF_COOKIE'] = token
        request.META['CSRF_COOKIE_USED'] = True
        return token

    def get(self, request, *args, **kwargs):
        serializer_class = CsrfSerializer
        csrf = self.get_or_create_csrf_token(request)
        csrf = csrf.decode('unicode-escape')
        print csrf
        return Response({
            'csrf': csrf,

        })

    def perform_create(self, serializer):
        user = serializer.validated_data['user']
        user = get_object_or_404(User, username=user)
        serializer.save(user=user)

    '''def post(self,request, *args, **kwargs):
        data_dict =  request.data
        user = data_dict['user']
        instance_user = get_object_or_404(User, username=user)
        name = data_dict['name']
        email = data_dict['email']
        phone = data_dict['phone']
        dob = data_dict['dob']
        profilePic = data_dict['profilePic']

        info = UserInfo(
            name= name,
            email= email,
            phone= phone,
            dob= dob,
            profilePic=profilePic,
            user=instance_user,
        )
        info.save()
        return Response(data_dict)'''


class EducationalAPIView(CreateAPIView):
    queryset = EducationInfo.objects.all()
    serializer_class = EducationInfoSerializer

    def get_or_create_csrf_token(self, request):
        token = request.META.get('CSRF_COOKIE', None)
        if token is None:
            token = csrf._get_new_csrf_key()
            request.META['CSRF_COOKIE'] = token
        request.META['CSRF_COOKIE_USED'] = True
        return token

    def get(self, request, *args, **kwargs):
        serializer_class = CsrfSerializer
        csrf = self.get_or_create_csrf_token(request)
        csrf = csrf.decode('unicode-escape')
        print csrf
        return Response({
            'csrf': csrf,

        })

    def post(self, request, *args, **kwargs):
        data_dict = (request.data)
        print data_dict
        user = data_dict['user']
        print user
        user = get_object_or_404(User, username=user)
        year = data_dict['year']
        agreegate = data_dict['agreegate']
        institution = data_dict['institution']
        degree = data_dict['degree']
        info = EducationInfo(
            user=user,
            year=year,
            agreegate=agreegate,
            institution=institution,
            degree=degree
        )
        info.save()
        return Response({"message": "Data Saved"})


class WorkExperienceAPIView(CreateAPIView):
    queryset = WorkExperience.objects.all()
    serializer_class = WorkExperienceSerializer

    def get_or_create_csrf_token(self, request):
        token = request.META.get('CSRF_COOKIE', None)
        if token is None:
            token = csrf._get_new_csrf_key()
            request.META['CSRF_COOKIE'] = token
        request.META['CSRF_COOKIE_USED'] = True
        return token

    def get(self, request, *args, **kwargs):
        serializer_class = CsrfSerializer
        csrf = self.get_or_create_csrf_token(request)
        csrf = csrf.decode('unicode-escape')
        print csrf
        return Response({
            'csrf': csrf,

        })

    def perform_create(self, serializer):
        user = serializer.validated_data['user']
        user = get_object_or_404(User, username=user)
        serializer.save(user=user)


class IntrestAPIView(CreateAPIView):
    queryset = Intrest.objects.all()
    serializer_class = IntrestSerializer

    def get_or_create_csrf_token(self, request):
        token = request.META.get('CSRF_COOKIE', None)
        if token is None:
            token = csrf._get_new_csrf_key()
            request.META['CSRF_COOKIE'] = token
        request.META['CSRF_COOKIE_USED'] = True
        return token

    def get(self, request, *args, **kwargs):
        serializer_class = CsrfSerializer
        csrf = self.get_or_create_csrf_token(request)
        csrf = csrf.decode('unicode-escape')
        print csrf
        return Response({
            'csrf': csrf,

        })

    def post(self, request, *args, **kwargs):
        data_dict = (request.data)
        print data_dict
        user = data_dict['user']
        user = get_object_or_404(User, username=user)
        intrest = data_dict['intrest']
        info = Intrest(
            user=user,
            intrest=intrest,
        )
        info.save()
        return Response({"message": "Data Saved"})


class SkillsAPIView(CreateAPIView):
    queryset = Skills.objects.all()
    serializer_class = SkillsSerializer

    def get_or_create_csrf_token(self, request):
        token = request.META.get('CSRF_COOKIE', None)
        if token is None:
            token = csrf._get_new_csrf_key()
            request.META['CSRF_COOKIE'] = token
        request.META['CSRF_COOKIE_USED'] = True
        return token

    def get(self, request, *args, **kwargs):
        serializer_class = CsrfSerializer
        csrf = self.get_or_create_csrf_token(request)
        csrf = csrf.decode('unicode-escape')
        print csrf
        return Response({
            'csrf': csrf,

        })

    def post(self, request, *args, **kwargs):
        data_dict = (request.data)
        user = data_dict['user']
        user = get_object_or_404(User, username=user)
        technical = data_dict['technical']
        soft = data_dict['soft']
        other = data_dict['other']
        info = Skills(
            user=user,
            technical=technical,
            soft=soft,
            other=other,
        )
        info.save()
        return Response({"message": "Data Saved"})


class CertificationAPIView(CreateAPIView):
    queryset = Certification.objects.all()
    serializer_class = CertificationSerializer

    def get_or_create_csrf_token(self, request):
        token = request.META.get('CSRF_COOKIE', None)
        if token is None:
            token = csrf._get_new_csrf_key()
            request.META['CSRF_COOKIE'] = token
        request.META['CSRF_COOKIE_USED'] = True
        return token

    def get(self, request, *args, **kwargs):
        serializer_class = CsrfSerializer
        csrf = self.get_or_create_csrf_token(request)
        csrf = csrf.decode('unicode-escape')
        print csrf
        return Response({
            'csrf': csrf,

        })

    def post(self, request, *args, **kwargs):
        data_dict = (request.data)
        user = data_dict['user']
        user = get_object_or_404(User, username=user)
        year_online = data_dict['year_online']
        agency_online = data_dict['agency_online']
        detail_online = data_dict['detail_online']
        year_offline = data_dict['year_offline']
        agency_offline = data_dict['agency_offline']
        detail_offline = data_dict['detail_offline']
        info = Certification(
            user=user,
            year_online=year_online,
            agency_online=agency_online,
            detail_online=detail_online,
            year_offline=year_offline,
            agency_offline=agency_offline,
            detail_offline=detail_offline,
        )
        info.save()
        return Response({"message": "Data Saved"})


class PublicationAPIView(CreateAPIView):
    queryset = Publication.objects.all()
    serializer_class = PublicationSerializer

    def get_or_create_csrf_token(self, request):
        token = request.META.get('CSRF_COOKIE', None)
        if token is None:
            token = csrf._get_new_csrf_key()
            request.META['CSRF_COOKIE'] = token
        request.META['CSRF_COOKIE_USED'] = True
        return token

    def get(self, request, *args, **kwargs):
        serializer_class = CsrfSerializer
        csrf = self.get_or_create_csrf_token(request)
        csrf = csrf.decode('unicode-escape')
        print csrf
        return Response({
            'csrf': csrf,

        })

    def post(self, request, *args, **kwargs):
        data_dict = (request.data)
        user = data_dict['user']
        user = get_object_or_404(User, username=user)
        year_national = data_dict['year_national']
        journal_national = data_dict['journal_national']
        detail_national = data_dict['detail_national']
        status_national = data_dict['status_national']
        year_international = data_dict['year_international']
        journal_international = data_dict['journal_international']
        detail_international = data_dict['detail_international']
        status_international = data_dict['status_international']
        info = Publication(
            user=user,
            year_national=year_national,
            journal_national=journal_national,
            detail_national=detail_national,
            status_national=status_national,
            year_international=year_international,
            journal_international=journal_international,
            detail_international=detail_international,
            status_international=status_international,
        )
        info.save()
        return Response({"message": "Data Saved"})


class PatentAPIView(CreateAPIView):
    queryset = Patent.objects.all()
    serializer_class = PatentSerializer

    def get_or_create_csrf_token(self, request):
        token = request.META.get('CSRF_COOKIE', None)
        if token is None:
            token = csrf._get_new_csrf_key()
            request.META['CSRF_COOKIE'] = token
        request.META['CSRF_COOKIE_USED'] = True
        return token

    def get(self, request, *args, **kwargs):
        serializer_class = CsrfSerializer
        csrf = self.get_or_create_csrf_token(request)
        csrf = csrf.decode('unicode-escape')
        print csrf
        return Response({
            'csrf': csrf,

        })

    def post(self, request, *args, **kwargs):
        data_dict = request.data
        user = data_dict['user']
        user = get_object_or_404(User, username=user)
        year_patent = data_dict['year_patent']
        detail_patent = data_dict['detail_patent']
        status_patent = data_dict['status_patent']
        patent_no = data_dict['patent_no']
        year_article = data_dict['year_article']
        journel_article = data_dict['journel_article']
        detail_article = data_dict['detail_article']
        info = Patent(
            user=user,
            year_patent=year_patent,
            detail_patent=detail_patent,
            status_patent=status_patent,
            patent_no=patent_no,
            year_article=year_article,
            journel_article=journel_article,
            detail_article=detail_article,
        )
        info.save()
        return Response({"message": "Data Saved"})


class BookAPIView(CreateAPIView):
    queryset = Books.objects.all()
    serializer_class = BooksSerializer

    def get_or_create_csrf_token(self, request):
        token = request.META.get('CSRF_COOKIE', None)
        if token is None:
            token = csrf._get_new_csrf_key()
            request.META['CSRF_COOKIE'] = token
        request.META['CSRF_COOKIE_USED'] = True
        return token

    def get(self, request, *args, **kwargs):
        serializer_class = CsrfSerializer
        csrf = self.get_or_create_csrf_token(request)
        csrf = csrf.decode('unicode-escape')
        return Response({
            'csrf': csrf,

        })

    def post(self, request, *args, **kwargs):
        data_dict = request.data
        user = data_dict['user']
        user = get_object_or_404(User, username=user)
        year_book = data_dict['year_book']
        publisher_book = data_dict['publisher_book']
        detail_book = data_dict['detail_book']
        isbn_book = data_dict['isbn_book']
        year_poster = data_dict['year_poster']
        org_poster = data_dict['org_poster']
        detail_poster = data_dict['detail_poster']
        info = Books(
            user=user,
            year_book=year_book,
            publisher_book=publisher_book,
            detail_book=detail_book,
            isbn_book=isbn_book,
            year_poster=year_poster,
            org_poster=org_poster,
            detail_poster=detail_poster,
        )
        info.save()
        return Response({"message": "Data Saved"})


class ConferenceAPIView(CreateAPIView):
    queryset = Conference.objects.all()
    serializer_class = ConferenceSerializer

    def get_or_create_csrf_token(self, request):
        token = request.META.get('CSRF_COOKIE', None)
        if token is None:
            token = csrf._get_new_csrf_key()
            request.META['CSRF_COOKIE'] = token
        request.META['CSRF_COOKIE_USED'] = True
        return token

    def get(self, request, *args, **kwargs):
        serializer_class = CsrfSerializer
        csrf = self.get_or_create_csrf_token(request)
        csrf = csrf.decode('unicode-escape')
        print csrf
        return Response({
            'csrf': csrf,

        })

    def post(self, request, *args, **kwargs):
        data_dict = request.data
        user = data_dict['user']
        user = get_object_or_404(User, username=user)
        year_c = data_dict['year_c']
        org_c = data_dict['org_c']
        detail_c = data_dict['detail_c']
        status_c = data_dict['status_c']
        year_i = data_dict['year_i']
        org_i = data_dict['org_i']
        detail_i = data_dict['detail_i']
        status_i = data_dict['status_i']
        info = Conference(
            user=user,
            year_c=year_c,
            org_c=org_c,
            detail_c=detail_c,
            status_c=status_c,
            year_i=year_i,
            org_i=org_i,
            detail_i=detail_i,
            status_i=status_i,
        )
        info.save()
        return Response({"message": "Data Saved"})


class AchievementAPIView(CreateAPIView):
    queryset = Achievement.objects.all()
    serializer_class = AchievementSerializer

    def get_or_create_csrf_token(self, request):
        token = request.META.get('CSRF_COOKIE', None)
        if token is None:
            token = csrf._get_new_csrf_key()
            request.META['CSRF_COOKIE'] = token
        request.META['CSRF_COOKIE_USED'] = True
        return token

    def get(self, request, *args, **kwargs):
        serializer_class = CsrfSerializer
        csrf = self.get_or_create_csrf_token(request)
        csrf = csrf.decode('unicode-escape')
        print csrf
        return Response({
            'csrf': csrf,

        })

    def post(self, request, *args, **kwargs):
        data_dict = request.data
        user = data_dict['user']
        user = get_object_or_404(User, username=user)
        year_a = data_dict['year_a']
        org_a = data_dict['org_a']
        detail_a = data_dict['detail_a']
        year_s = data_dict['year_s']
        org_s = data_dict['org_s']
        detail_s = data_dict['detail_s']

        info = Achievement(
            user=user,
            year_a=year_a,
            org_a=org_a,
            detail_a=detail_a,
            year_s=year_s,
            org_s=org_s,
            detail_s=detail_s,
        )
        info.save()
        return Response({"message": "Data Saved"})


class ExtraCurricularAPIView(CreateAPIView):
    queryset = Extracurricular.objects.all()
    serializer_class = ExtraCurricularSerializer

    def get_or_create_csrf_token(self, request):
        token = request.META.get('CSRF_COOKIE', None)
        if token is None:
            token = csrf._get_new_csrf_key()
            request.META['CSRF_COOKIE'] = token
        request.META['CSRF_COOKIE_USED'] = True
        return token

    def get(self, request, *args, **kwargs):
        serializer_class = CsrfSerializer
        csrf = self.get_or_create_csrf_token(request)
        csrf = csrf.decode('unicode-escape')
        print csrf
        return Response({
            'csrf': csrf,

        })

    def perform_create(self, serializer):
        user = serializer.validated_data['user']
        user = get_object_or_404(User, username=user)
        serializer.save(user=user)


class SocialMediaLinksAPIView(CreateAPIView):
    queryset = SocialMediaLinks.objects.all()
    serializer_class = SocialMediaLinksSerializer

    def get_or_create_csrf_token(self, request):
        token = request.META.get('CSRF_COOKIE', None)
        if token is None:
            token = csrf._get_new_csrf_key()
            request.META['CSRF_COOKIE'] = token
        request.META['CSRF_COOKIE_USED'] = True
        return token

    def get(self, request, *args, **kwargs):
        serializer_class = CsrfSerializer
        csrf = self.get_or_create_csrf_token(request)
        csrf = csrf.decode('unicode-escape')
        print csrf
        return Response({
            'csrf': csrf,

        })

    def perform_create(self, serializer):
        user = serializer.validated_data['user']
        user = get_object_or_404(User, username=user)
        serializer.save(user=user)