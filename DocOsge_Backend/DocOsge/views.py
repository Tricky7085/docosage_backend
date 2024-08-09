from django.contrib.auth.models import Group, User
from .models import LoginUsers, UserAccountTypes, Users, UserInformation, AccountTypes, DoctorInformation, Appointment
# Appointment, Attachment
from rest_framework import permissions, viewsets, filters
# from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import status
from rest_framework.response import Response
from DocOsge_Backend.DocOsge.serializers import (
    GroupSerializer, UserSerializer,
    UsersSerializer,AccountTypesSerializer, UserSignInSerializer, PasswordResetSerializer, UserInformationSerializer, CookieTokenRefreshSerializer, DoctorInformationSerializer, AppointmentSerializer)

from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from django.conf import settings
from datetime import timedelta
from django.db.models import Q
from rest_framework_simplejwt.exceptions import InvalidToken
# from django.contrib.auth.models import AnonymousUser
from .middlewares import CustomJWTAuthentication
from rest_framework_simplejwt.views import TokenRefreshView
from django.contrib.auth.hashers import make_password, check_password
from django.utils.dateparse import parse_datetime
# from rest_framework.authtoken.models import Token
# from rest_framework.permissions import IsAuthenticated

class UserViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows users to be viewed or edited.
    """
    queryset = User.objects.all().order_by('-date_joined')
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]


class GroupViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows groups to be viewed or edited.
    """
    queryset = Group.objects.all()
    serializer_class = GroupSerializer
    permission_classes = [permissions.IsAuthenticated]

# class LoginUserViewSet(viewsets.ModelViewSet):
#     """
#     API endpoint that allows Login users to be viewed or edited.
#     """
#     queryset = LoginUsers.objects.all()
#     serializer_class = LoginUserSerializer
#     permission_classes = [permissions.IsAuthenticated]


class RegisterUserViewSet(viewsets.ViewSet):
   
#    permission_classes = [IsAuthenticated]
#    queryset = Users.objects.all()
#    serializer_class = UsersSerializer
   
   def create(self, request):
      
        userData = request.data

        try:
            if(userData.get("account_type") != 'doctor' and userData.get("account_type") != 'customer'):
                return Response("Invalid account_type",status=status.HTTP_400_BAD_REQUEST)
            
            userSerializer = UsersSerializer(data=userData, context={'request': request})
            if(userSerializer.is_valid()):
                user = userSerializer.save()
            else:
                return Response(userSerializer.errors,status=status.HTTP_400_BAD_REQUEST)

            accountTypeSerializer = AccountTypesSerializer(data=userData,context={'request': request})
            if(accountTypeSerializer.is_valid()):
                account_type = accountTypeSerializer.save()
            else:
                return Response(accountTypeSerializer.errors,status=status.HTTP_400_BAD_REQUEST)
            user_account_type = UserAccountTypes(user_id=user.user_id, account_type_id=account_type.account_type_id)
            user_account_type.save()

            response_data = userSerializer.data
            response_data.update(accountTypeSerializer.data)

            refresh = RefreshToken.for_user(user)
            response_data['access'] = str(refresh.access_token)
            response_data['refresh'] = str(refresh)

            response = Response(response_data, status=status.HTTP_201_CREATED)
            response.set_cookie(
                key='refresh',
                value=str(refresh),
                httponly=True,
                secure=False,
                samesite='Lax',
                domain='127.0.0.1',
                path='/',
                expires=settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME']
            )
            return response
        except Exception as error:
            return Response({"error":str(error)},status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    


class UserLoginViewSet(viewsets.ViewSet):
    # permission_classes = [IsAuthenticated]
    # serializer_class = UserSignInSerializer

    def create(self, request):
        serializer = UserSignInSerializer(data=request.data)
        
        try:
            if(serializer.is_valid()):
                email = serializer.validated_data.get('email')
                password = serializer.validated_data.get('password')

                try:
                    user = Users.objects.get(email=email)
                    user_dict = Users.objects.filter(email=email).values().first()

                    if(check_password(password, user_dict.get("password_hash"))):

                        user_dict.pop("password_hash")

                        refresh = RefreshToken.for_user(user)
                        user_dict['access'] = str(refresh.access_token)
                        user_dict['refresh'] = str(refresh)

                        response = Response(user_dict,status=status.HTTP_200_OK)

                        return response
                    else:
                        return Response("invalid credentials",status=status.HTTP_406_NOT_ACCEPTABLE)
                except Exception as error:
                    return Response('Invalid credential', status=status.HTTP_400_BAD_REQUEST)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as error:
            return Response({"error": str(error)}, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetRequestViewSet(viewsets.ViewSet):
    
    def create(self,request, *args, **kwargs):
        
        try:
            passwordResetSerializer = PasswordResetSerializer(data=request.data)
            
            if(passwordResetSerializer.is_valid()):
                try:
                    user = Users.objects.get(email = passwordResetSerializer.validated_data.get('email'))
                    
                    refresh = RefreshToken.for_user(user)
                    token = refresh.access_token
                    token.set_exp(lifetime=timedelta(minutes=5))
                    token["email"] = user.email
                    
                    
                    return Response({"url":f'{settings.FRONTEND_URL}/passwordreset/?email={user.email}&user={token}'},status=status.HTTP_200_OK)
                    
                except Users.DoesNotExist:
                    return Response({"error":"User not found"}, status=status.HTTP_404_NOT_FOUND)
                
            else:
                return Response(passwordResetSerializer.errors,status=status.HTTP_400_BAD_REQUEST)
            
        except Exception as error:
            return Response({"error":str(error)},status=status.HTTP_400_BAD_REQUEST)                    


class PasswordResetConfirmViewSet(viewsets.ViewSet):
    
    def password_reset(self,request):
        
        newPassword = request.data.get("newPassword")
        
        try:
            token = request.data.get('user')
    
            access_token = AccessToken(token)
            user_email = access_token["email"]
            
            try:
                user = Users.objects.get(email=user_email)
                user.password_hash = make_password(newPassword)
                user.save()

                return Response("Password updated successfully", status=status.HTTP_200_OK)
            except Users.DoesNotExist:
                return Response("No user found with this email", status=status.HTTP_404_NOT_FOUND)
            
        except Exception as error:
            return Response(str(error),status=status.HTTP_400_BAD_REQUEST)
        

class UserInfoUpdateViewSet(viewsets.ViewSet):
    authentication_classes = [CustomJWTAuthentication]
    # permission_classes = [IsAuthenticated]
    
    def create(self,request):
        
        if request.user is None:
            return Response({"error":"Unauthorized"},status=status.HTTP_401_UNAUTHORIZED)
        
        verifiedUser = request.user
        request.data["user"] = verifiedUser["user_id"]
        
        
        userInfoSerializer = UserInformationSerializer(data=request.data)
        
        try:
            user = UserInformation.objects.get(user_id=verifiedUser["user_id"])
            if(user):
                request.data.pop('user')
                
                for key, value in request.data.items():
                    setattr(user,key,value)
                user.save()
                return Response("user info updated",status=status.HTTP_200_OK)
            
        except:
            if(userInfoSerializer.is_valid()):
                userInfoSerializer.save()
                return Response("user info created",status=status.HTTP_200_OK)
            else:
                return Response(userInfoSerializer.errors,status=status.HTTP_400_BAD_REQUEST)
            

class CustomTokenRefreshView(TokenRefreshView):
    
    serializer_class = CookieTokenRefreshSerializer
        
    def post(self,request,*args, **kwargs):
        
        serializer = self.get_serializer(data=request.data,context={'request':request})
        
        try:
            serializer.is_valid(raise_exception=True)
        except InvalidToken as e:
            return Response({"detail":str(e)},status=status.HTTP_401_UNAUTHORIZED)
        
        return Response(serializer.validated_data, status=status.HTTP_200_OK)

class LogoutUserView(viewsets.ViewSet):
    
    def create(self,request):
        
        response = Response({"message":"User logout successfull"}, status=status.HTTP_200_OK)
        response.delete_cookie(
            key="refresh",
        )
        return response


class DoctorInfoView(viewsets.ViewSet):
    
    def create(self, request):
        user_id = request.data.get("user")

        if not user_id:
            return Response({"message": "User ID is required"}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            user = Users.objects.get(pk=user_id)
        except Users.DoesNotExist:
            return Response({"message": "User does not exist"}, status=status.HTTP_404_NOT_FOUND)
        
        account_type = UserAccountTypes.objects.filter(user=user).first()
        if not account_type or account_type.account_type.account_type != 'doctor':
            return Response({"message": "User is not a doctor"}, status=status.HTTP_400_BAD_REQUEST)

        doctorInfoSerializer = DoctorInformationSerializer(data=request.data)

        if doctorInfoSerializer.is_valid():
            doctorInfoSerializer.save()
            return Response({'message': "Doctor info created"}, status=status.HTTP_201_CREATED)
        else:
            return Response(doctorInfoSerializer.errors, status=status.HTTP_400_BAD_REQUEST)

class DoctorSearchViewSet(viewsets.ModelViewSet):
    queryset = DoctorInformation.objects.all()
    serializer_class = DoctorInformationSerializer

    def get_queryset(self):
        queryset = super().get_queryset()
        params = self.request.query_params
        
        name = params.get('name', None)
        practice_type = params.get('practiceType', None)

        query = Q()

        if name:
            query &= Q(user__name__icontains=name)
        
        if practice_type:
            query &= Q(practiceType__icontains=practice_type)

        queryset = queryset.filter(query)

        print(f"Filtered Queryset: {queryset.query}")

        return queryset


class AppointmentViewSet(viewsets.ViewSet):
    authentication_classes = [CustomJWTAuthentication]

    def create(self, request):
        user = request.user
        data = request.data

        doctor_id = data.get('doctor')
        appointment_date = data.get('appointment_date')
        appointment_time = data.get('appointment_time')
        title = data.get('title')
        description = data.get('description')

        if not doctor_id or not appointment_date or not appointment_time or not title:
            return Response({"error": "Missing required fields"}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            doctor = DoctorInformation.objects.get(pk=doctor_id)
        except DoctorInformation.DoesNotExist:
            return Response({"error": "Doctor does not exist"}, status=status.HTTP_404_NOT_FOUND)

        appointment = Appointment(
            user=user,
            doctor=doctor,
            appointment_date=appointment_date,
            appointment_time=appointment_time,
            title=title,
            description=description
        )
        appointment.save()

        serializer = AppointmentSerializer(appointment)
        return Response(serializer.data, status=status.HTTP_201_CREATED)
