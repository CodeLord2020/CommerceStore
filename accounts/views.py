from django.shortcuts import render
from .utils import *
from .models import User, UserContactInfo, Token
from django.db import transaction
from django.conf import settings
from rest_framework.permissions import AllowAny, IsAuthenticated, IsAdminUser
from rest_framework import generics, status, views
from django.shortcuts import get_object_or_404
from rest_framework.exceptions import APIException
from .serializers import *
from .tokens import create_jwt_pair_for_user
from rest_framework.request import Request
from rest_framework.response import Response
# Create your views here.
from django.contrib.auth import get_user_model


# class UserRegisteration(generics.CreateAPIView):
#     serializer_class = UserRegisterSerilaizer
#     permission_classes = (AllowAny, )
    
#     def post(self, request, *args, **kwargs):
#         serializer = self.get_serializer(data=request.data)
#         serializer.is_valid(raise_exception=True)

#     @transaction.atomic
#     def perform_create(self, serializer):
#         data = {}
#         user = serializer.save()
#         user_data = serializer.data
#         token, created = Token.objects.update_or_create(
#             user=user,
#             token_type='ACCOUNT_VERIFICATION',
#             defaults={'user': user, 'token_type': 'ACCOUNT_VERIFICATION'},
#         )
#         token.generate_random_token()
#         verification_url = f"{settings.CLIENT_URL}/accounts/auth/verify_account/?token={token.token}"
        
#         try:
#             send_verification_mail(user.email, verify_link=verification_url)
#         except Exception as e:
#                 # If an error occurs during email sending, rollback the transaction
#             user.delete()
#             message = "There was an error with sending the verification email. Please try registering again."
#             raise APIException(detail=message, code=status.HTTP_400_BAD_REQUEST)
        
#         data['user'] = user_data
#         data['message'] = "Registration Successful!, Login after verifying your account "

#         return Response(data, status.HTTP_201_CREATED)
    



class UserRegistration(generics.CreateAPIView):
    serializer_class = UserRegisterSerilaizer
    permission_classes = (AllowAny,)

    @transaction.atomic
    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            user = serializer.save()
            token, _ = Token.objects.update_or_create(
                user=user,
                token_type='ACCOUNT_VERIFICATION',
                defaults={'token_type': 'ACCOUNT_VERIFICATION'}
            )
            token.generate_random_token()
            verification_url = f"{settings.CLIENT_URL}/accounts/auth/verify_account/?token={token.token}"

            send_verification_mail(user.email, verify_link=verification_url)

            return Response({
                'user': serializer.data,
                'message': "Registration Successful! Please verify your account using the email we sent."
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            # If an error occurs, rollback the transaction
            transaction.set_rollback(True)
            error_message = "There was an error during registration. Please try again."
            raise APIException(detail=error_message, code=status.HTTP_500_INTERNAL_SERVER_ERROR)


class RegisterAdminView(generics.CreateAPIView):
    '''
    API endpoint for admin registration.
    '''
    queryset = get_user_model().objects.all()
    serializer_class = AdminRegisterSerializer
    permission_classes = (AllowAny, )

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response(data=serializer.data, status=status.HTTP_201_CREATED)
        return Response(data=serializer.errors)




class VerifyUserEmail(generics.GenericAPIView):
    """Endpoint to verify the token and set user verified field to True"""

    permission_classes = [AllowAny]
    serializer_class = VerifyTokenSerializer

    def post(self, request: Request):
        data = request.data
        serializer = self.serializer_class(data=data)

        if serializer.is_valid():
            verification_token = Token.objects.filter(
                token=serializer.validated_data["token"]
            ).first()
            if verification_token:
                user = verification_token.user
                if user.is_verified:
                    return Response(
                        {"message": "Account is already verified"},
                        status=status.HTTP_400_BAD_REQUEST,
                    )
                else:
                    user.is_verified = True
                    user.save()
                    return Response(
                        {"message": "Account Verified Successfully"}, status=status.HTTP_200_OK
                    )
            else:
                return Response(
                    {'success': True, 'message': "Token not found"},
                    status=status.HTTP_404_NOT_FOUND,
                )
        return Response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class LoginView(generics.GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = LoginUserSerializer

    def post(self, request: Request):
        data = request.data
        serializer = self.serializer_class(data=data)

        if serializer.is_valid():
            email = serializer.validated_data["email"]
            password = serializer.validated_data["password"]

            user = authenticate(email=email, password=password)

            if user is not None:
                if user.is_verified:
                    tokens = create_jwt_pair_for_user(user)

                    response = {
                        "message": "Login Successful",
                        "tokens": tokens,
                        **UserDetailSerilaizer(instance=user).data,
                    }

                    return Response(data=response, status=status.HTTP_200_OK)
                else:
                    return Response(
                        data={"message": "User account not verified"},
                        status=status.HTTP_401_UNAUTHORIZED,
                    )
            else:
                return Response(
                    data={"message": "Invalid email or password"},
                    status=status.HTTP_401_UNAUTHORIZED,
                )
            
        return Response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LogoutBlacklistTokenUpdateView(generics.GenericAPIView):
    serializer_class = LogoutUserSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save() 
        return Response(status=status.HTTP_204_NO_CONTENT)
    




class ForgotPasswordView(views.APIView):
    permission_classes = [AllowAny]
    serializer_class = ForgotPasswordSerializer

    def post(self, request: Request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data["email"]
            user = get_object_or_404(User, email=email)
            token, _ = Token.objects.update_or_create(
                user=user,
                token_type='PASSWORD_RESET',
                defaults={'user': user, 'token_type': 'PASSWORD_RESET'},
            )

            token.generate_random_token()
            reset_url = f"{settings.CLIENT_URL}/accounts/auth/password-reset/?token={token.token}"

            send_passwordchange_mail(email=email, reset_link=reset_url)

            return Response(
                {"message": "Password reset link sent successfully"}, status=status.HTTP_200_OK
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    


class ResetPasswordView(generics.GenericAPIView):
    serializer_class = PasswordResetConfirmSerializer
    permission_classes = [AllowAny]

    def post(self, request: Request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            new_password = serializer.validated_data["new_password"]
            token = serializer.validated_data["token"]
            user_token = Token.objects.filter(token=token).first()
            if not user_token:
                return Response(
                    {"error": "token not found or Invalid token"}, status=status.HTTP_404_NOT_FOUND
                )
            user_token.reset_user_password(new_password)
            return Response({"message": "Password reset successfully"}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class AllAdminsView(generics.ListAPIView):
    '''
    API endpoint for Listing all Admins. Only available to other `admin` usertypes.
    '''
    serializer_class = UserCompleteInfoSerilaizer
    permission_classes = (IsAdminUser,)

    def get(self, request):
        queryset = get_user_model().objects.filter(is_staff=True)
        serializer = self.serializer_class(queryset, many=True)
        return Response(data=serializer.data, status=status.HTTP_200_OK)


class AdminDetailView(generics.RetrieveUpdateDestroyAPIView):
    '''
    Retrieve, Update or Delete an `admin` usertype. Only available to other `admin` usertypes.
    '''
    look_up = 'pk'
    serializer_class = UserCompleteInfoSerilaizer
    queryset = get_user_model().objects.filter(is_staff=True)
    permission_classes = (IsAdminUser,)



class UserDetailView(generics.RetrieveUpdateDestroyAPIView):
    '''Retrieve, Update or Delete a regular `user`. Only available to `admin` usertype.'''
    look_up = 'pk'
    serializer_class = UserCompleteInfoSerilaizer
    queryset = get_user_model().objects.filter(is_staff=False)
    permission_classes = (IsAdminUser,)