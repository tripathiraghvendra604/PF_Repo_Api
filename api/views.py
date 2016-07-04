from django.shortcuts import render
from rest_framework import permissions, viewsets, status, views
from .models import User, UserInfo, EducationInfo, WorkExperience, Intrest
from .permissions import IsAccountOwner
from .serializers import (UserSerializer,
                          UserInfoSerializer,
                          EducationInfoSerializer,
                          CsrfSerializer,
                          UserLoginSerializer,
                          WorkExperienceSerializer,
                          IntrestSerializer)

from rest_framework.response import Response
from rest_framework.generics import CreateAPIView
from django.middleware import csrf
from django.contrib.auth import authenticate, login, logout


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

    # def create(self, request):
    #     serializer = self.serializer_class(data=request.data)
    #
    #     if serializer.is_valid():
    #         User.objects.create_user(**serializer.validated_data)
    #
    #         return Response(serializer.validated_data, status=status.HTTP_201_CREATED)
    #
    #     return Response({
    #         'status': 'Bad request',
    #         'message': 'Account could not be created with received data.'
    #     }, status=status.HTTP_400_BAD_REQUEST)


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
        print username, password
        account = authenticate(username=username, password=password)
        if account is not None:
            login(request, account)
            print 'u are logged in:  '
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

    def post(self, request, format=None):
        logout(request)
        print 'logged out'
        return Response({}, status=status.HTTP_204_NO_CONTENT)


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
        serializer.save(user=self.request.user)



            #def post(self, request, *args, **kwargs):
        #
        # data_dict =  request.data
        # name = data_dict['name']
        # email = data_dict['email']
        # phone = data_dict['phone']
        # dob = data_dict['dob']
        # profilePic = data_dict['profilePic']
        #
        # info = UserInfo(
        #     name= name,
        #     email= email,
        #     phone= phone,
        #     dob= dob,
        #     profilePic=profilePic
        # )
        # info.save()
        # return Response(data_dict)


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
        serializer.save(user = self.request.user)


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
        serializer.save(user=self.request.user)


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