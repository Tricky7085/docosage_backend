from rest_framework_simplejwt.authentication import JWTAuthentication
from .models import Users

class CustomJWTAuthentication(JWTAuthentication):
    def get_user(self, validated_token):
        user_id = validated_token.get('user_id')
        if(user_id is None):
            raise Exception("User id not found in token")
        try:
            user = Users.objects.get(user_id=user_id)
            return {"user_id":user.user_id,"email":user.email}
        except Users.DoesNotExist:
            raise Exception("User does not exist")