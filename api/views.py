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
                          AchievementSerializer, UserLogoutSerializer,
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
        '''print request.user, request.session['member_id']
        logout(request)
        return Response({'message': 'Logged Out!'}, status=status.HTTP_200_OK)'''
        data_dict = request.data
        exist_user = data_dict['user']
        user = User.objects.get(username=exist_user)
        [s.delete() for s in Session.objects.all() if str(s.get_decoded().get('_auth_user_id')) == str(user.id)]
        return Response({'message': 'Logged Out!'}, status=status.HTTP_200_OK)


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

    def perform_create(self, serializer):
        user = serializer.validated_data['user']
        user = get_object_or_404(User, username=user)
        serializer.save(user=user)


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

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


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

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


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

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


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

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


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

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


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

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


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

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


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

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


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
        serializer.save(user=self.request.user)


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
        serializer.save(user=self.request.user)