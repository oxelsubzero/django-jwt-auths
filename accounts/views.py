from rest_framework.generics import GenericAPIView
from .serializers import UserRegisterSerializer, LoginUserSerializer, PasswordResetSerializer,SetNewPasswordSerializer
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django.utils.encoding import smart_str,DjangoUnicodeDecodeError
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_decode
from .models import User

class RegisterUserView(GenericAPIView):
    serializer_class = UserRegisterSerializer

    def post(self,request):
        user_data = request.data
        serializer = self.serializer_class(data=user_data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            user = serializer.data
            #send email function 
            return Response({
                'data':user,
                'message':f'hi  thanks for signing up a passcode'
            }, status=status.HTTP_201_CREATED)
        
        return Response(serializer.erros,status=status.HTTP_400_BAD_REQUEST)


class LoginUserView(GenericAPIView) :
    serializer_class = LoginUserSerializer
    def post(self,request):
        serializer = self.serializer_class(data=request.data,context={'request':request})
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data,status=status.HTTP_200_OK)
    

class Test(GenericAPIView):
    permission_classes = [IsAuthenticated]
    def get(self,request):
        data = {
            'msg':'its works' }
        return Response(data,status=status.HTTP_200_OK)
    
class PasswordResetView(GenericAPIView):
    serializer_class = PasswordResetSerializer

    def post(self, request):
        # Instantiate the serializer with request data and context
        serializer = self.serializer_class(data=request.data, context={'request': request})
        
        # Validate the data, raising an exception if validation fails
        serializer.is_valid(raise_exception=True)
        
        # If validation is successful, return a success response
        return Response({'message': "A link has been sent to your email to reset."})

    

class PasswordResetConfirm(GenericAPIView):
    def get(self,request,uidb64,token):
        try :
            user_id =smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=user_id)
            if not PasswordResetTokenGenerator().check_token(user,token):
                return Response({'message':'token is invalid or expired'},status=status.HTTP_401_UNAUTHORIZED)
            return Response({'success':True,'message':'credentials is valid','uidb64':uidb64,'token':token},status=status.HTTP_200_OK)
        except DjangoUnicodeDecodeError:
            return Response({'message':'token is invalid or expired'},status=status.HTTP_401_UNAUTHORIZED)


class SetNewPassword(GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)  # Instantiate the serializer with request data
        serializer.is_valid(raise_exception=True)  # Validate the serializer data, raising an exception if validation fails
        serializer.save()  # Perform actions specified in the serializer's validate method
        return Response({'message': 'Password reset successful'}, status=status.HTTP_200_OK)
    
"""class LogoutUserView(GenericAPIView):
    serializer_class = LoginUserSerializer
    permission_classes = [IsAuthenticated]

    def post(self,request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(status=status.HTTP_204_NO_CONTENT)"""