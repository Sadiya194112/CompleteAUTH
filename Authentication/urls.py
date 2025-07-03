
from django.contrib import admin
from django.urls import path,include
from app.views import *

urlpatterns = [
    path('admin/', admin.site.urls),
    
    path('authentication/signup/', RegistrationView.as_view(), name='signup'),
    path('authentication/login/', LoginView.as_view(), name='login'),
    path('send-otp/', SendOTPView.as_view()),
    path('verify-otp/', VerifyOTPView.as_view()),
    path('change-password/<int:id>/', ChangePasswordView.as_view()),
     path('request-password-reset/', RequestResetPasswordView.as_view(), name='request-password-reset'),
    path('reset-password/<uuid:token>/', ResetPasswordView.as_view(), name='reset-password'),
]
