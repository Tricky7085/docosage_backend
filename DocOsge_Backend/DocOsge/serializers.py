from django.contrib.auth.models import Group, User
from .models import LoginUsers,Users,AccountTypes,UserAccountTypes,SocialAccounts, UserInformation, Appointment, Attachment
from rest_framework import serializers

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


class DoctorSearchSerializer(serializers.ModelSerializer):
    class Meta:
        model = Users
        fields = ['name', 'email', 'phone_number']

class AttachmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Attachment
        fields = ['file',]

class AppointmentSerializer(serializers.ModelSerializer):
    attachments = AttachmentSerializer(many=True, read_only=True)

    class Meta:
        model = Appointment
        fileds = ['doctor', 'appointment_date', 'appointment_time', 'title', 'description', 'user', 'attachments']





