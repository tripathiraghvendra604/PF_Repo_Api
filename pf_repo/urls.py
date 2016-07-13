"""pf_repo URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.9/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""
from django.conf.urls import url, include
from django.contrib import admin
from api.views import (UserViewSet,
                       UserInfoAPIView, UserUpdateViewSet,
                       EducationalAPIView, EducationalUpdateAPIView,
                       LoginView, LogoutView, PasswordResetView,
                       WorkExperienceAPIView, IntrestAPIView, PosterAPIView,
                       SkillsAPIView, CertificationAPIView, PublicationAPIView, ArticleAPIView,
                       PatentAPIView, BookAPIView, ConferenceAPIView, AchievementAPIView,
                       ExtraCurricularAPIView, SocialMediaLinksAPIView)
from django.conf import settings
from django.conf.urls.static import static


urlpatterns = [
    url(r'^admin/', admin.site.urls),
    url(r'^api/accounts/', UserViewSet.as_view(), name='register'),
    url(r'^accounts/login', LoginView.as_view(), name='login'),
    url(r'^accounts/logout', LogoutView.as_view(), name='logout'),
    url(r'^password_reset', PasswordResetView.as_view(), name='password_reset'),
    url(r'^create/$', UserInfoAPIView.as_view(), name='user_info'),
    url(r'^(?P<username>[\w.@+-]+)/create/$', UserUpdateViewSet.as_view(), name='user_info_edit'), #update
    url(r'^education/', EducationalAPIView.as_view(), name='education_info'),
    url(r'^(?P<username>[\w.@+-]+)/education/', EducationalUpdateAPIView.as_view(), name='education_info_update'),
    url(r'^work/', WorkExperienceAPIView.as_view(), name='work'),
    url(r'^intrest/', IntrestAPIView.as_view(), name='intrest'),
    url(r'^skills/', SkillsAPIView.as_view(), name='skills'),
    url(r'^certification/', CertificationAPIView.as_view(), name='certification'),
    url(r'^publication/', PublicationAPIView.as_view(), name='publication'),
    url(r'^patent/', PatentAPIView.as_view(), name='patent'),
    url(r'^article/$', ArticleAPIView.as_view(), name='article'),
    url(r'^book/', BookAPIView.as_view(), name='book'),
    url(r'^poster/', PosterAPIView.as_view(), name='poster'),
    url(r'^conference/', ConferenceAPIView.as_view(), name='conference'),
    url(r'^achievement/', AchievementAPIView.as_view(), name='achievement'),
    url(r'^extracurricular/', ExtraCurricularAPIView.as_view(), name='extracurricular'),
    url(r'^links/', SocialMediaLinksAPIView.as_view(), name='links'),

]

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)