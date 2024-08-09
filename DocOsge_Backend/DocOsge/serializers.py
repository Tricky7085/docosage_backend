from django.contrib.auth.models import Group, User
from .models import LoginUsers,Users,AccountTypes,UserAccountTypes,SocialAccounts, UserInformation, DoctorInformation, Appointment 

from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenRefreshSerializer
from rest_framework_simplejwt.exceptions import InvalidToken


class UserSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = User
        fields = ['url', 'username', 'email', 'groups']


class GroupSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = Group
        fields = ['url', 'name']

# class LoginUserSerializer(serializers.HyperlinkedModelSerializer):
#     class Meta:
#         model = LoginUsers
#         fields = ['url', 'loginId', 'loginName']


class UsersSerializer(serializers.ModelSerializer):
    class Meta:
        model = Users
        # fields = ['user_id',"name","email",'phone_number']
        fields = "__all__"
        extra_kwargs = {
            'password_hash':{'write_only':True}
        }

class AccountTypesSerializer(serializers.ModelSerializer):
    class Meta:
        model = AccountTypes
        fields = ['account_type_id','account_type']

class UserSignInSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)


class PasswordResetSerializer(serializers.Serializer):
    
    email = serializers.EmailField()    

class UserInformationSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserInformation
        fields = '__all__'             

class CookieTokenRefreshSerializer(TokenRefreshSerializer):
    refresh = None
    
    def validate(self, attrs):
        
        request = self.context['request']
        refresh_token = request.COOKIES.get('refresh')
        
        if not refresh_token:
            raise InvalidToken('No valid token found in cookie "refresh"')
        
        attrs['refresh'] = refresh_token
        return super().validate(attrs)
    
class DoctorInformationSerializer(serializers.ModelSerializer):
    user_name = serializers.CharField(source='user.name', read_only=True)

    class Meta:
        model = DoctorInformation
        fields = [
            'id', 'user_name', 'age', 'gender', 'qualification', 
            'yearsOfExperience', 'registrationYear', 'registrationNumber',
            'registeredCouncil', 'practiceType', 'clinicAddress', 'clinicZipCode'
        ]

class AppointmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Appointment
        fields = ['id', 'user', 'doctor', 'appointment_date', 'appointment_time', 'title', 'description', 'created_at']





