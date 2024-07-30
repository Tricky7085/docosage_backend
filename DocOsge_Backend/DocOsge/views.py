from django.contrib.auth.models import Group, User
from .models import LoginUsers, UserAccountTypes, Users, UserInformation, Appointment, Attachment
from rest_framework import permissions, viewsets
from rest_framework import status
from rest_framework.response import Response
from DocOsge_Backend.DocOsge.serializers import (
    GroupSerializer, UserSerializer,
    UsersSerializer,AccountTypesSerializer, UserSignInSerializer, PasswordResetSerializer, UserInformationSerializer,
    DoctorSearchSerializer, AppointmentSerializer)
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from django.conf import settings
from .middlewares import CustomJWTAuthentication
from rest_framework_simplejwt.views import TokenRefreshView
from django.contrib.auth.hashers import make_password, check_password
from django.utils.dateparse import parse_datetime
# from rest_framework.authtoken.models import Token
# from rest_framework.permissions import IsAuthenticated
from rest_framework.filters import SearchFilter
# from django.utils.http import urlsafe_base64_encode
# from django.utils.encoding import force_bytes
# from django.contrib.auth.tokens import default_token_generator
# from django.utils import timezone

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
        
    def post(self,request,*args, **kwargs):
        
        # print(request.COOKIES.get('refresh'))
        
        # refresh_token = request.COOKIES.get('refresh_token')
        
        # if refresh_token is None:
        #     return Response({"error": "No refresh token found in cookies"}, status=status.HTTP_400_BAD_REQUEST)
        # cookie = request.COOKIES.get('refresh_token')
        
        response = super().post(request, *args, **kwargs)
        
        
        data = response.data
        
        # refresh_token = data.get("refresh")
        
        
        return Response(data,status=status.HTTP_200_OK)



class DoctorSearchViewSet(viewsets.ViewSet):
    serializer_class = DoctorSearchSerializer
    # permission_classes = [permissions.IsAuthenticated]

    def list(self, request):
        search_query = request.query_params.get('search', None)

        if search_query:
            queryset = Users.objects.filter(
                useraccounttypes__account_type__account_type='doctor',
                name__icontains=search_query
            )

            if queryset.exists():
                serializer = DoctorSearchSerializer(queryset, many=True)
                return Response(serializer.data, status=status.HTTP_200_OK)
            else:
                return Response({"message": "No doctors found with this name"}, status=status.HTTP_400_BAD_REQUEST)
            
        else:
            return Response({"message": "Search query parameter is required"}, status=status.HTTP_400_BAD_REQUEST)    


class BookAppointmentViewSet(viewsets.ViewSet):
    # permission_classes = [IsAuthenticated]

    def create(self, request):

        data = {
            'doctor_name' : request.data.get('doctor_name'),
            'appointment_date' : request.data.get('appointment_date'),
            'appointment_time' : request.data.get('appointment_time'),
            'title' : request.data.get('title'),
            'description' : request.data.get('description'),
            'user' : request.user.id
       
        }

        serializer = AppointmentSerializer(data=data)

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        doctor_name = data.get('doctor_name')
        appointment_date = data.get('appointment_date')
        appointment_time = data.get('appointment_time')
        title = data.get('title')
        description = data.get('description')


        try:
            doctor = Users.objects.get(name=doctor_name, useraccounttypes__account_type__account_type='doctor')
        except Users.DoesNotExist:
            return Response({'error': 'Doctor not found'}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            appointment_date = parse_datetime(appointment_date)
            appointment_time = parse_datetime(appointment_time)
            if not appointment_date or not appointment_time:
                return Response({"error": "Invalid date or time format"}, status=status.HTTP_400_BAD_REQUEST)
        except ValueError:
            return Response({"error": "Invalid date or time format"}, status=status.HTTP_400_BAD_REQUEST)

        
        appointment = Appointment(
            doctor=doctor,
            appointment_date=appointment_date,
            appointment_time=appointment_time,
            title=title,
            description=description,
            user=request.user
        )
        appointment.save()

        
        attachments = request.FILES.getlist('attachments')
        for file in attachments:
            if file.size > 5 * 1024 * 1024:
                return Response({"error": "File size exceeds the limit"}, status=status.HTTP_400_BAD_REQUEST)
            if file.content_type not in ['application/pdf', 'image/jpeg', 'image/png', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document']:
                return Response({"error": "Unsupported file type"}, status=status.HTTP_400_BAD_REQUEST)
            Attachment.objects.create(appointment=appointment, file=file)

        # Optionally send a confirmation email (commented out for now)
        # send_mail(
        #     'Appointment Confirmation',
        #     f'Your appointment with Dr. {doctor_name} has been successfully booked for {appointment_date} at {appointment_time}.',
        #     settings.DEFAULT_FROM_EMAIL,
        #     [request.user.email, doctor.email],
        #     fail_silently=False,
        # )

        return Response({"message": "Appointment booked successfully"}, status=status.HTTP_201_CREATED)










        # try:
        #     doctor_name = request.data.get('doctor_name')
        #     appointment_date = request.data.get('appointment_date')
        #     appointment_time = request.data.get('appointment_time')
        #     title = request.data.get('title')
        #     description = request.data.get('description')
        #     attachments = request.data.get('attachments')

        #     if not all([doctor_name, appointment_date, appointment_time, title, description, attachments]):
        #         return Response({'message': 'Missing required filed'}, status=status.HTTP_400_BAD_REQUEST)
        
        #     try:
        #         doctor = Users.objects.get(name=doctor_name, useraccounttypes__account_type__account_type='doctor')
        #     except Users.DoesNotExist:
        #         return Response({'error': 'Doctor not found'}, status=status.HTTP_400_BAD_REQUEST)

        #     try:
        #         appointment_date = parse_date(appointment_date, '%Y-%m-%dT%H:%M:%SZ')
        #         appointment_time = parse_date(appointment_time, '%Y-%m-%dT%H:%M:%SZ')
        #     except ValueError:
        #         return Response({'error': 'Invalid date or time format'}, status=status.HTTP_400_BAD_REQUEST)


        #     appointment = Appointment(
        #         doctor=doctor,
        #         appointment_date=appointment_date,
        #         appointment_time=appointment_time,
        #         title=title,
        #         description=description,
        #         attachments=attachments
        #     )
        #     appointment.save()

        #     for file in attachments:
        #         if file.size > 5 * 1024 * 1024:
        #             return Response({'error': 'file size exceeds the limit'}, status=status.HTTP_400_BAD_REQUEST)
        #         if file.content_type not in ['application/pdf', 'image/png', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document']:
        #             return Response({'error': 'Unsupported file type'}, status=status.HTTP_400_BAD_REQUEST)
        #         Attachment.objects.create(appointment=appointment, file=file)



        #     return Response({'message': 'Appointment booked successfully'}, status=status.HTTP_201_CREATED)
        # except:
        #     return Response({'message': "Internal server error"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)