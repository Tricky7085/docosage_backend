from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, AuthenticationFailed
from .models import Users

class CustomJWTAuthentication(JWTAuthentication):
    def get_user(self, validated_token):
        try:
            user_id = validated_token.get('user_id')  
            if user_id is None:
                raise AuthenticationFailed("User ID not found in token")

            user = Users.objects.get(user_id=user_id)
            return user 
        except Users.DoesNotExist:
            raise AuthenticationFailed("User does not exist")
        except Exception as e:
            raise AuthenticationFailed(str(e))

    def authenticate(self, request):
        header = self.get_header(request)
        if header is None:
            return None

        raw_token = self.get_raw_token(header)
        if raw_token is None:
            return None

        validated_token = self.get_validated_token(raw_token)
        return self.get_user(validated_token), validated_token
