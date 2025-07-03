from django.shortcuts import render
from django.shortcuts import get_object_or_404
from .serializer import *
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .emails import *
from django.contrib.auth import get_user_model
from .models import PasswordReset
from django.contrib.auth import authenticate
from .serializer import RegistrationSerializer, UserLoginSerializer, RequestResetPasswordSerializer, ResetPasswordSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import AuthenticationFailed

def get_tokens_for_user(user):
    if not user.is_active:
      raise AuthenticationFailed("User is not active")

    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

class RegistrationView(APIView):
    def post(self, request):
        serializer = RegistrationSerializer(data = request.data)
        if serializer.is_valid():
            user = serializer.save()
            return Response({
                'msg': 'User created successfully'
            }, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    
    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            password = serializer.validated_data['password']
            user = authenticate(email=email, password=password)

            if user is not None:
                token = get_tokens_for_user(user)
                return Response({
                    'token': token,
                    'msg': 'Login successful',
                }, status=status.HTTP_200_OK)
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class SendOTPView(APIView):
    
    def post(self, request):
        try:
            serializer = RequestResetPasswordSerializer(data=request.data)
            if serializer.is_valid():
                email = serializer.validated_data['email']
                user = get_object_or_404(User, email=email)
                if user:
                    send_otp(serializer.data['email'])
                return Response({'msg': 'OTP Sent!'}, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            print(e)
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class VerifyOTPView(APIView):
    def post(self, request):
        try:
            serializer = VerifyAccountSerializer(data=request.data)
            if serializer.is_valid():
                email = serializer.data['email']
                otp = serializer.data['otp']
                
                user = get_object_or_404(User, email=email)

    
                if user.otp != otp:
                    return Response({'msg':"Wrong Otp"}, status=status.HTTP_400_BAD_REQUEST)

                user.is_verified = True
                user.save()
                
                return Response({'msg': 'Account verified successfully'}, status=status.HTTP_200_OK)
            
        except Exception as e:
            print(e)
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class ChangePasswordView(APIView):
    def post(self, request, id):
        password = request.data.get('password')
        new_password = request.data.get('new_password')
        
        try:
            user = get_user_model().objects.get(pk=id)
        except get_user_model().DoesNotExist:
            return Response({'msg': 'User not found'}, status=404)
        
        
        if not user.check_password(password):
            return Response({'error': 'Incorrect current password'}, status=400)

        user.set_password(new_password)
        user.save()
        return Response({'success': 'Password changed successfully'}, status=200)



User = get_user_model()

class RequestResetPasswordView(APIView):
    def post(self, request):
        serializer = RequestResetPasswordSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            user = User.objects.filter(email=email).first()
 
            if user:
                reset_obj = PasswordReset.objects.create(email=email)
                reset_link = f"http://localhost:8000/reset-password/{reset_obj.token}/"
                
                send_mail(
                    subject="Reset your password",
                    message=f"Click the link to reset your password: {reset_link}",
                    from_email="taspiyasultana194112@gmail.com",
                    recipient_list=[email]   
                )
            return Response({'success': 'A reset link has been sent.'}, status=200)

        return Response(serializer.errors, status=400)
    

class ResetPasswordView(APIView):
    def post(self, request, token):
        serializer = ResetPasswordSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=400)
        
        reset_obj = PasswordReset.objects.filter(token=token).first()
        if not reset_obj:
            return Response({'error': 'Invalid or expired token'}, status=400)
        
        user = User.objects.filter(email=reset_obj.email).first()
        
        if user:
            user.set_password(serializer.validated_data['new_password'])
            user.save()
            reset_obj.delete()
            return Response({'success': 'Password has been reset successfully'})
        return Response({'error': 'User not found'}, status=404)

        
                