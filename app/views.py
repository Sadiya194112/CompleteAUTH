from django.shortcuts import render
from .serializer import *
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .emails import *

class RegisterView(APIView):
    
    def post(self, request):
        try:
            serializer = UserSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                send_otp(serializer.data['email'])
                return Response({'msg': 'Registration Successful!'}, status=status.HTTP_201_CREATED)
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
                
                user = User.objects.filter(email=email)
                if not user.exists():
                    return Response({'msg':"Invalid email"}, status=status.HTTP_400_BAD_REQUEST)

                if user[0].otp != otp:
                    return Response({'msg':"Wrong Otp"}, status=status.HTTP_400_BAD_REQUEST)

                user[0].is_verified = True
                user[0].save()
                
                return Response({'msg': 'Account verified successfully'}, status=status.HTTP_200_OK)
            
        except Exception as e:
            print(e)
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
