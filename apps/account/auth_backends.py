from rest_framework.authentication import TokenAuthentication
from rest_framework.exceptions import AuthenticationFailed

AUTH_COOKIE_KEY = 'authorization'


class CookieTokenAuthBackend(TokenAuthentication):
    def authenticate(self, request):
        token = request.COOKIES.get(AUTH_COOKIE_KEY, None)
        if not token:
            return None

        return self.authenticate_credentials(token)