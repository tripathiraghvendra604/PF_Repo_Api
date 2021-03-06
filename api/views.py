from django.shortcuts import render, get_object_or_404
from rest_framework import permissions, viewsets, status, views
from .models import (User, UserInfo, EducationInfo, WorkExperience, Intrest,
                     Skills, Certification, Publication, Patent, Books, Article,
                     Conference, Achievement, Extracurricular, SocialMediaLinks,
                     Poster)
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
                          BooksSerializer, ArticleSerializer, PosterSerializer,
                          ConferenceSerializer,
                          AchievementSerializer, UserLogoutSerializer, PasswordResetSerializer,
                          ExtraCurricularSerializer, SocialMediaLinksSerializer)


from rest_framework.response import Response
from rest_framework.generics import CreateAPIView, RetrieveAPIView
from django.middleware import csrf
from django.contrib.auth import authenticate, login, logout
from django.contrib.sessions.models import Session
from django.core.mail import send_mail


class UserViewSet(CreateAPIView):
    lookup_field = 'username'
    queryset = User.objects.all()
    serializer_class = UserSerializer

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
                send_mail('Account Registered', 'You are successfully registered in PF-Repo',
                          'tripathiraghav604@gmail.com', [email], fail_silently=False)
                print 'mail send'
                return Response({
                    'status': 'Account Created',
                    'message': 'User Registered'
                })

        return Response({
            'status': 'Bad request',
            'message': 'Account could not be created with received data.'
        }, status=status.HTTP_400_BAD_REQUEST)


class UserUpdateViewSet(views.APIView):
    serializer_class = UserInfoSerializer

    def get(self, request, username, *args, **kwargs):
        user = get_object_or_404(User, username=username)
        info = UserInfo.objects.get(user=user)
        data = dict()
        data['name'] = info.name
        data['email'] = info.email
        data['phone'] = info.phone
        data['dob'] = info.dob
        try:
            data['profilePic'] = info.profilePic.url
        except:
            data['profilePic'] = ''

        return Response(data)

    def post(self, request, username, *args, **kwargs):
        user = get_object_or_404(User, username=username)
        instance = UserInfo.objects.get(user=user)
        data = request.data
        instance.name = self.request.data['name']
        instance.email = self.request.data['email']
        instance.phone = self.request.data['phone']
        instance.dob = self.request.data['dob']
        instance.profilePic = self.request.data['profilePic']
        instance.save()
        return Response({"message": "Data Saved"})


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
    serializer_class = UserLogoutSerializer

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


class EducationalUpdateAPIView(views.APIView):
    serializer_class = EducationInfoSerializer

    def get(self, request, username, *args, **kwargs):
        user = get_object_or_404(User, username=username)
        #info = EducationInfo.objects.get(user=user)
        info = get_object_or_404(EducationInfo, user=user)
        data = dict()
        data['year'] = info.year
        data['degree'] = info.degree
        data['agreegate'] = info.agreegate
        data['institution'] = info.institution

        return Response(data)

    def post(self, request, username, *args, **kwargs):
        user = get_object_or_404(User, username=username)
        instance = get_object_or_404(EducationInfo, user=user)
        data = request.data
        instance.year = self.request.data['year']
        instance.degree = self.request.data['degree']
        instance.agreegate = self.request.data['agreegate']
        instance.institution = self.request.data['institution']
        instance.save()
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

    def post(self, request, *args, **kwargs):
        data_dict = request.data
        user = data_dict['user']
        user = get_object_or_404(User, username=user)
        from_intern = data_dict['from_intern']
        to_intern = data_dict['to_intern']
        company_intern = data_dict['company_intern']
        title_intern = data_dict['title_intern']
        status_intern = data_dict['status_intern']
        from_job = data_dict['from_job']
        to_job = data_dict['to_job']
        company_job = data_dict['company_job']
        title_job = data_dict['title_job']
        from_freelancer = data_dict['from_freelancer']
        to_freelancer = data_dict['to_freelancer']
        client_freelancer = data_dict['client_freelancer']
        project_freelancer = data_dict['project_freelancer']
        status_freelancer = data_dict['status_freelancer']
        from_self = data_dict['from_self']
        to_self = data_dict['to_self']
        project_self = data_dict['project_self']
        status_self = data_dict['status_self']

        info = WorkExperience(
            user=user,
            from_intern=from_intern,
            to_intern=to_intern,
            company_intern=company_intern,
            title_intern=title_intern,
            status_intern=status_intern,
            from_job=from_job,
            to_job=to_job,
            company_job=company_job,
            title_job=title_job,
            from_freelancer=from_freelancer,
            to_freelancer=to_freelancer,
            client_freelancer=client_freelancer,
            project_freelancer=project_freelancer,
            status_freelancer=status_freelancer,
            from_self=from_self,
            to_self=to_self,
            project_self=project_self,
            status_self=status_self,
        )
        info.save()
        return Response({"message": "Data Saved"})


class WorkExperienceUpdateAPIView(views.APIView):
    serializer_class = WorkExperienceSerializer

    def get(self, request, username, *args, **kwargs):
        user = get_object_or_404(User, username=username)
        info = get_object_or_404(WorkExperience, user=user)
        data = dict()
        data['from_intern'] = info.from_intern
        data['to_intern'] = info.to_intern
        data['company_intern'] = info.company_intern
        data['title_intern'] = info.title_intern
        data['status_intern'] = info.status_intern

        data['from_job'] = info.from_job
        data['to_job'] = info.to_job
        data['company_job'] = info.company_job
        data['title_job'] = info.title_job

        data['from_freelancer'] = info.from_freelancer
        data['to_freelancer'] = info.to_freelancer
        data['client_freelancer'] = info.client_freelancer
        data['project_freelancer'] = info.project_freelancer
        data['status_freelancer'] = info.status_freelancer

        data['from_self'] = info.from_self
        data['to_self'] = info.to_self
        data['project_self'] = info.project_self
        data['status_self'] = info.status_self

        return Response(data)

    def post(self, request, username, *args, **kwargs):
        user = get_object_or_404(User, username=username)
        instance = get_object_or_404(WorkExperience, user=user)
        data = request.data
        instance.from_intern = self.request.data['from_intern']
        instance.to_intern = self.request.data['to_intern']
        instance.company_intern = self.request.data['company_intern']
        instance.title_intern = self.request.data['title_intern']
        instance.status_intern = self.request.data['status_intern']

        instance.from_job = self.request.data['from_job']
        instance.to_job = self.request.data['to_job']
        instance.company_job = self.request.data['company_job']
        instance.title_job = self.request.data['title_job']

        instance.from_freelancer = self.request.data['from_freelancer']
        instance.to_freelancer = self.request.data['to_freelancer']
        instance.client_freelancer = self.request.data['client_freelancer']
        instance.project_freelancer = self.request.data['project_freelancer']
        instance.status_freelancer = self.request.data['status_freelancer']

        instance.from_self = self.request.data['from_self']
        instance.to_self = self.request.data['to_self']
        instance.project_self = self.request.data['project_self']
        instance.status_self = self.request.data['status_self']

        instance.save()
        return Response({"message": "Data Saved"})


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


class IntrestUpdateAPIView(views.APIView):
    serializer_class = IntrestSerializer

    def get(self, request, username, *args, **kwargs):
        user = get_object_or_404(User, username=username)
        info = get_object_or_404(Intrest, user=user)
        data = dict()
        data['intrest'] = info.intrest

        return Response(data)

    def post(self, request, username, *args, **kwargs):
        user = get_object_or_404(User, username=username)
        instance = get_object_or_404(Intrest, user=user)
        data = request.data
        instance.intrest = self.request.data['intrest']
        instance.save()
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


class SkillsUpdateAPIView(views.APIView):
    serializer_class = SkillsSerializer

    def get(self, request, username, *args, **kwargs):
        user = get_object_or_404(User, username=username)
        info = get_object_or_404(Skills, user=user)
        data = dict()
        data['technical'] = info.technical
        data['soft'] = info.soft
        data['other'] = info.other

        return Response(data)

    def post(self, request, username, *args, **kwargs):
        user = get_object_or_404(User, username=username)
        instance = get_object_or_404(Skills, user=user)
        data = request.data
        instance.technical = self.request.data['technical']
        instance.soft = self.request.data['soft']
        instance.other = self.request.data['other']
        instance.save()
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
        year = data_dict['year']
        agency = data_dict['agency']
        details = data_dict['details']
        mode = data_dict['mode']
        info = Certification(
            user=user,
            year=year,
            agency=agency,
            details=details,
            mode=mode,
        )
        info.save()
        return Response({"message": "Data Saved"})


class CertificationUpdateAPIView(views.APIView):
    serializer_class = CertificationSerializer

    def get(self, request, username, *args, **kwargs):
        user = get_object_or_404(User, username=username)
        info = get_object_or_404(Certification, user=user)
        data = dict()
        data['year'] = info.year
        data['agency'] = info.agency
        data['details'] = info.details
        data['mode'] = info.mode

        return Response(data)

    def post(self, request, username, *args, **kwargs):
        user = get_object_or_404(User, username=username)
        instance = get_object_or_404(Certification, user=user)
        data = request.data
        instance.year = self.request.data['year']
        instance.agency = self.request.data['agency']
        instance.details = self.request.data['details']
        instance.mode = self.request.data['mode']
        instance.save()
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
        year = data_dict['year']
        journal = data_dict['journal']
        details = data_dict['details']
        status = data_dict['status']
        level = data_dict['level']
        info = Publication(
            user=user,
            year=year,
            journal=journal,
            status=status,
            details=details,
            level=level,
        )
        info.save()
        return Response({"message": "Data Saved"})


class PublicationUpdateAPIView(views.APIView):
    serializer_class = PublicationSerializer

    def get(self, request, username, *args, **kwargs):
        user = get_object_or_404(User, username=username)
        info = get_object_or_404(Publication, user=user)
        data = dict()
        data['year'] = info.year
        data['journal'] = info.journal
        data['details'] = info.details
        data['status'] = info.status
        data['level'] = info.level

        return Response(data)

    def post(self, request, username, *args, **kwargs):
        user = get_object_or_404(User, username=username)
        instance = get_object_or_404(Publication, user=user)
        data = request.data
        instance.year = self.request.data['year']
        instance.journal = self.request.data['journal']
        instance.details = self.request.data['details']
        instance.status = self.request.data['status']
        instance.level = self.request.data['level']
        instance.save()
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
        year = data_dict['year']
        details = data_dict['details']
        status = data_dict['status']
        patent_no = data_dict['patent_no']

        info = Patent(
            user=user,
            year=year,
            details=details,
            status=status,
            patent_no=patent_no,
        )
        info.save()
        return Response({"message": "Data Saved"})


class PatentUpdateAPIView(views.APIView):
    serializer_class = PatentSerializer

    def get(self, request, username, *args, **kwargs):
        user = get_object_or_404(User, username=username)
        info = get_object_or_404(Patent, user=user)
        data = dict()
        data['year'] = info.year
        data['patent_no'] = info.patent_no
        data['details'] = info.details
        data['status'] = info.status

        return Response(data)

    def post(self, request, username, *args, **kwargs):
        user = get_object_or_404(User, username=username)
        instance = get_object_or_404(Patent, user=user)
        data = request.data
        instance.year = self.request.data['year']
        instance.patent_no = self.request.data['patent_no']
        instance.details = self.request.data['details']
        instance.status = self.request.data['status']
        instance.save()
        return Response({"message": "Data Saved"})


class ArticleAPIView(CreateAPIView):
    queryset = Article.objects.all()
    serializer_class = ArticleSerializer

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
        year = data_dict['year']
        details = data_dict['details']
        publisher = data_dict['publisher']
        title = data_dict['title']
        links = data_dict['links']

        info = Article(
            user=user,
            year=year,
            details=details,
            publisher=publisher,
            title=title,
            links=links,
        )
        info.save()
        return Response({"message": "Data Saved"})


class ArticleUpdateAPIView(views.APIView):
    serializer_class = ArticleSerializer

    def get(self, request, username, *args, **kwargs):
        user = get_object_or_404(User, username=username)
        info = get_object_or_404(Article, user=user)
        data = dict()
        data['year'] = info.year
        data['details'] = info.details
        data['publisher'] = info.publisher
        data['title'] = info.title
        data['links'] = info.links

        return Response(data)

    def post(self, request, username, *args, **kwargs):
        user = get_object_or_404(User, username=username)
        instance = get_object_or_404(Article, user=user)
        data = request.data
        instance.year = self.request.data['year']
        instance.details = self.request.data['details']
        instance.publisher = self.request.data['publisher']
        instance.title = self.request.data['title']
        instance.links = self.request.data['links']
        instance.save()
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
        year = data_dict['year']
        title = data_dict['title']
        publisher = data_dict['publisher']
        detail = data_dict['detail']
        isbn = data_dict['isbn']
        links = data_dict['links']

        info = Books(
            user=user,
            year=year,
            publisher=publisher,
            detail=detail,
            isbn=isbn,
            links=links,
            title=title
            )
        info.save()
        return Response({"message": "Data Saved"})


class BookUpdateAPIView(views.APIView):
    serializer_class = BooksSerializer

    def get(self, request, username, *args, **kwargs):
        user = get_object_or_404(User, username=username)
        info = get_object_or_404(Books, user=user)
        data = dict()
        data['year'] = info.year
        data['title'] = info.title
        data['publisher'] = info.publisher
        data['detail'] = info.detail
        data['isbn'] = info.isbn
        data['links'] = info.links

        return Response(data)

    def post(self, request, username, *args, **kwargs):
        user = get_object_or_404(User, username=username)
        instance = get_object_or_404(Books, user=user)
        instance.year = self.request.data['year']
        instance.title = self.request.data['title']
        instance.publisher = self.request.data['publisher']
        instance.detail = self.request.data['detail']
        instance.isbn = self.request.data['isbn']
        instance.links = self.request.data['links']
        instance.save()
        return Response({"message": "Data Saved"})


class PosterAPIView(CreateAPIView):
    queryset = Poster.objects.all()
    serializer_class = PosterSerializer

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
        year = data_dict['year']
        title = data_dict['title']
        org = data_dict['org']
        detail = data_dict['detail']
        link = data_dict['link']

        info = Poster(
            user=user,
            year=year,
            org=org,
            detail=detail,
            link=link,
            title=title,
            )
        info.save()
        return Response({"message": "Data Saved"})


class PosterUpdateAPIView(views.APIView):
    serializer_class = PosterSerializer

    def get(self, request, username, *args, **kwargs):
        user = get_object_or_404(User, username=username)
        info = get_object_or_404(Poster, user=user)
        data = dict()
        data['year'] = info.year
        data['title'] = info.title
        data['org'] = info.org
        data['detail'] = info.detail
        data['link'] = info.link

        return Response(data)

    def post(self, request, username, *args, **kwargs):
        user = get_object_or_404(User, username=username)
        instance = get_object_or_404(Poster, user=user)
        instance.year = self.request.data['year']
        instance.title = self.request.data['title']
        instance.org = self.request.data['org']
        instance.detail = self.request.data['detail']
        instance.link = self.request.data['link']
        instance.save()
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
        title_c = data_dict['title_c']
        year_i = data_dict['year_i']
        org_i = data_dict['org_i']
        detail_i = data_dict['detail_i']
        status_i = data_dict['status_i']
        title_i = data_dict['title_i']
        info = Conference(
            user=user,
            year_c=year_c,
            org_c=org_c,
            detail_c=detail_c,
            status_c=status_c,
            title_c=title_c,
            year_i=year_i,
            org_i=org_i,
            detail_i=detail_i,
            status_i=status_i,
            title_i=title_i,
        )
        info.save()
        return Response({"message": "Data Saved"})


class ConferenceUpdateAPIView(views.APIView):
    serializer_class = ConferenceSerializer

    def get(self, request, username, *args, **kwargs):
        user = get_object_or_404(User, username=username)
        info = get_object_or_404(Conference, user=user)
        data = dict()
        data['year_c'] = info.year_c
        data['org_c'] = info.org_c
        data['detail_c'] = info.detail_c
        data['status_c'] = info.status_c
        data['title_c'] = info.title_c

        data['year_i'] = info.year_i
        data['org_i'] = info.org_i
        data['detail_i'] = info.detail_i
        data['status_i'] = info.status_i
        data['title_i'] = info.title_i

        return Response(data)

    def post(self, request, username, *args, **kwargs):
        user = get_object_or_404(User, username=username)
        instance = get_object_or_404(Conference, user=user)
        instance.year_c = self.request.data['year_c']
        instance.org_c = self.request.data['org_c']
        instance.detail_c = self.request.data['detail_c']
        instance.status_c = self.request.data['status_c']
        instance.title_c = self.request.data['title_c']

        instance.year_i = self.request.data['year_i']
        instance.org_i = self.request.data['org_i']
        instance.detail_i = self.request.data['detail_i']
        instance.status_i = self.request.data['status_i']
        instance.title_i = self.request.data['title_i']

        instance.save()
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


class AchievemntUpdateAPIView(views.APIView):
    serializer_class = AchievementSerializer

    def get(self, request, username, *args, **kwargs):
        user = get_object_or_404(User, username=username)
        info = get_object_or_404(Achievement, user=user)
        data = dict()
        data['year_a'] = info.year_a
        data['org_a'] = info.org_a
        data['detail_a'] = info.detail_a

        data['year_s'] = info.year_s
        data['org_s'] = info.org_s
        data['detail_s'] = info.detail_s

        return Response(data)

    def post(self, request, username, *args, **kwargs):
        user = get_object_or_404(User, username=username)
        instance = get_object_or_404(Achievement, user=user)
        instance.year_a = self.request.data['year_a']
        instance.org_a = self.request.data['org_a']
        instance.detail_a = self.request.data['detail_a']

        instance.year_s = self.request.data['year_s']
        instance.org_s = self.request.data['org_s']
        instance.detail_s = self.request.data['detail_s']

        instance.save()
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

    def post(self, request, *args, **kwargs):
        data_dict = request.data
        user = data_dict['user']
        user = get_object_or_404(User, username=user)
        year_e = data_dict['year_e']
        org_e = data_dict['org_e']
        details_e = data_dict['details_e']
        year_v = data_dict['year_v']
        org_v = data_dict['org_v']
        details_v = data_dict['details_v']

        info = Extracurricular(
            user=user,
            year_e=year_e,
            org_e=org_e,
            details_e=details_e,
            year_v=year_v,
            org_v=org_v,
            details_v=details_v,
        )
        info.save()
        return Response({"message": "Data Saved"})


class ExtraCurricularUpdateAPIView(views.APIView):
    serializer_class = ExtraCurricularSerializer

    def get(self, request, username, *args, **kwargs):
        user = get_object_or_404(User, username=username)
        info = get_object_or_404(Extracurricular, user=user)
        data = dict()
        data['year_e'] = info.year_e
        data['org_e'] = info.org_e
        data['details_e'] = info.details_e

        data['year_v'] = info.year_v
        data['org_v'] = info.org_v
        data['details_v'] = info.details_v

        return Response(data)

    def post(self, request, username, *args, **kwargs):
        user = get_object_or_404(User, username=username)
        instance = get_object_or_404(Extracurricular, user=user)
        instance.year_e = self.request.data['year_e']
        instance.org_e = self.request.data['org_e']
        instance.details_e = self.request.data['details_e']

        instance.year_v = self.request.data['year_v']
        instance.org_v = self.request.data['org_v']
        instance.details_v = self.request.data['details_v']

        instance.save()
        return Response({"message": "Data Saved"})


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

    def post(self, request, *args, **kwargs):
        data_dict = request.data
        user = data_dict['user']
        user = get_object_or_404(User, username=user)
        links = data_dict['links']

        info = SocialMediaLinks(
            user=user,
            links=links,
        )
        info.save()
        return Response({"message": "Data Saved"})


class SocialMediaLinksUpdateAPIView(views.APIView):
    serializer_class = SocialMediaLinksSerializer

    def get(self, request, username, *args, **kwargs):
        user = get_object_or_404(User, username=username)
        info = get_object_or_404(SocialMediaLinks, user=user)
        data = dict()
        data['links'] = info.links
        return Response(data)

    def post(self, request, username, *args, **kwargs):
        user = get_object_or_404(User, username=username)
        instance = get_object_or_404(SocialMediaLinks, user=user)
        instance.links = self.request.data['links']
        instance.save()
        return Response({"message": "Data Saved"})


class RetrieveUserInfoApiView(views.APIView):

    def get(self, request, username, *args, **kwargs):
        user = get_object_or_404(User, username=username)
        data = dict()
        #for userinfo
        try:
            #info = get_object_or_404(UserInfo, user=user)
            info = UserInfo.objects.get(user=user)
            data['name'] = info.name
            data['email'] = info.email
            data['phone'] = info.phone
            data['dob'] = info.dob
            try:
                data['profilePic'] = info.profilePic.url
            except:
                data['profilePic'] = 'not added'

        except:
            data['name'] = 'not added'
            data['email'] = 'not added'
            data['phone'] = 'not added'
            data['dob'] = 'not added'
            data['profilePic'] = 'not added'

        #for education info
        try:
            info = EducationInfo.objects.get(user=user)
            data['year'] = info.year
            data['degree'] = info.degree
            data['agreegate'] = info.agreegate
            data['institution'] = info.institution
        except:
            data['year'] = 'not added'
            data['degree'] = 'not added'
            data['agreegate'] = 'not added'
            data['institution'] = 'not added'

        #for work experience
        try:
            info = WorkExperience.objects.get(user=user)
            data['from_intern'] = info.from_intern
            data['to_intern'] = info.to_intern
            data['company_intern'] = info.company_intern
            data['title_intern'] = info.title_intern
            data['status_intern'] = info.status_intern

            data['from_job'] = info.from_job
            data['to_job'] = info.to_job
            data['company_job'] = info.company_job
            data['title_job'] = info.title_job

            data['from_freelancer'] = info.from_freelancer
            data['to_freelancer'] = info.to_freelancer
            data['client_freelancer'] = info.client_freelancer
            data['project_freelancer'] = info.project_freelancer
            data['status_freelancer'] = info.status_freelancer

            data['from_self'] = info.from_self
            data['to_self'] = info.to_self
            data['project_self'] = info.project_self
            data['status_self'] = info.status_self
        except:
            data['from_intern'] = 'not added'
            data['to_intern'] = 'not added'
            data['company_intern'] = 'not added'
            data['title_intern'] = 'not added'
            data['status_intern'] = 'not added'

            data['from_job'] = 'not added'
            data['to_job'] = 'not added'
            data['company_job'] = 'not added'
            data['title_job'] = 'not added'

            data['from_freelancer'] = 'not added'
            data['to_freelancer'] = 'not added'
            data['client_freelancer'] = 'not added'
            data['project_freelancer'] = 'not added'
            data['status_freelancer'] = 'not added'

            data['from_self'] = 'not added'
            data['to_self'] = 'not added'
            data['project_self'] = 'not added'
            data['status_self'] = 'not added'

        #for intrest
        try:
            info = Intrest.objects.get(user=user)
            data['intrest'] = info.intrest
        except:
            data['intrest'] = 'not added'


        #for skills
        try:
            info = Skills.objects.get(user=user)
            data['technical'] = info.technical
            data['soft'] = info.soft
            data['other'] = info.other
        except:
            data['technical'] = 'not added'
            data['soft'] = 'not added'
            data['other'] = 'not added'

        #for certification
        try:
            info = Certification.objects.get(user=user)
            data['year'] = info.year
            data['agency'] = info.agency
            data['details'] = info.details
            data['mode'] = info.mode
        except:
            data['year'] = 'not added'
            data['agency'] = 'not added'
            data['details'] = 'not added'
            data['mode'] = 'not added'

        #for publication
        try:
            info = Publication.objects.get(user=user)
            data['year'] = info.year
            data['journal'] = info.journal
            data['details'] = info.details
            data['status'] = info.status
            data['level'] = info.level
        except:
            data['year'] = 'not added'
            data['journal'] = 'not added'
            data['details'] = 'not added'
            data['status'] = 'not added'
            data['level'] = 'not added'

        # for patent
        try:
            info = Patent.objects.get(user=user)
            data['year'] = info.year
            data['patent_no'] = info.patent_no
            data['details'] = info.details
            data['status'] = info.status
        except:
            data['year'] = 'not added'
            data['patent_no'] = 'not added'
            data['details'] = 'not added'
            data['status'] = 'not added'

        #for article
        try:
            info = Article.objects.get(user=user)
            data['year'] = info.year
            data['details'] = info.details
            data['publisher'] = info.publisher
            data['title'] = info.title
            data['links'] = info.links
        except:
            data['year'] = 'not added'
            data['details'] = 'not added'
            data['publisher'] = 'not added'
            data['title'] = 'not added'
            data['links'] = 'not added'

        #for books
        try:
            info = Books.objects.get(user=user)
            data['year'] = info.year
            data['title'] = info.title
            data['publisher'] = info.publisher
            data['detail'] = info.detail
            data['isbn'] = info.isbn
            data['links'] = info.links
        except:
            data['year'] = 'not added'
            data['title'] = 'not added'
            data['publisher'] = 'not added'
            data['detail'] = 'not added'
            data['isbn'] = 'not added'
            data['links'] = 'not added'

        #for poster
        try:
            info = Poster.objects.get(user=user)
            data['year'] = info.year
            data['title'] = info.title
            data['org'] = info.org
            data['detail'] = info.detail
            data['link'] = info.link
        except:
            data['year'] = 'not added'
            data['title'] = 'not added'
            data['org'] = 'not added'
            data['detail'] = 'not added'
            data['link'] = 'not added'

        #for conference
        try:
            info = Conference.objects.get(user=user)
            data['year_c'] = info.year_c
            data['org_c'] = info.org_c
            data['detail_c'] = info.detail_c
            data['status_c'] = info.status_c
            data['title_c'] = info.title_c

            data['year_i'] = info.year_i
            data['org_i'] = info.org_i
            data['detail_i'] = info.detail_i
            data['status_i'] = info.status_i
            data['title_i'] = info.title_i
        except:
            data['year_c'] = 'not added'
            data['org_c'] = 'not added'
            data['detail_c'] = 'not added'
            data['status_c'] = 'not added'
            data['title_c'] = 'not added'

            data['year_i'] = 'not added'
            data['org_i'] = 'not added'
            data['detail_i'] = 'not added'
            data['status_i'] = 'not added'
            data['title_i'] = 'not added'

        #for achievement
        try:
            info = Achievement.objects.get(user=user)
            data['year_a'] = info.year_a
            data['org_a'] = info.org_a
            data['detail_a'] = info.detail_a

            data['year_s'] = info.year_s
            data['org_s'] = info.org_s
            data['detail_s'] = info.detail_s

        except:
            data['year_a'] = 'not added'
            data['org_a'] = 'not added'
            data['detail_a'] = 'not added'

            data['year_s'] = 'not added'
            data['org_s'] = 'not added'
            data['detail_s'] = 'not added'

        # extracurricular
        try:
            info = Extracurricular.objects.get(user=user)
            data['year_e'] = info.year_e
            data['org_e'] = info.org_e
            data['details_e'] = info.details_e

            data['year_v'] = info.year_v
            data['org_v'] = info.org_v
            data['details_v'] = info.details_v
        except:
            data['year_e'] = 'not added'
            data['org_e'] = 'not added'
            data['details_e'] = 'not added'

            data['year_v'] = 'not added'
            data['org_v'] = 'not added'
            data['details_v'] = 'not added'

        # for social links
        try:
            info = SocialMediaLinks(user=user)
            data['links'] = info.links
        except:
            data['links'] = 'not added'


        return Response(data)