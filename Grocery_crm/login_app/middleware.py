from django.http import JsonResponse
import jwt
from django.conf import settings

class TokenRequiredMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Skip token validation for login or public endpoints
        public_paths = [
            '/api/login_user/',  # Login API
            '/api/register/',  # Registration API (if applicable)
            '/',  # Login page
            '/welcome/',  # Welcome page
            '/sales/',  # Sales page
            '/plot-sales/',  # Sales plot API
        ]
        if request.path in public_paths:
            return self.get_response(request)

        # Check for Authorization header
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return JsonResponse({'error': 'Token required'}, status=401)

        token = auth_header.split(' ')[1]
        try:
            # Decode the token
            jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return JsonResponse({'error': 'Token has expired'}, status=401)
        except jwt.InvalidTokenError:
            return JsonResponse({'error': 'Invalid token'}, status=401)

        return self.get_response(request)
from django.http import HttpResponse   
class IgnoreWellKnownRequestsMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.path.startswith('/.well-known/'):
            return HttpResponse(status=401)  # Return 401 Unauthorized for these requests
        return self.get_response(request)   
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
import jwt
from django.conf import settings
from .models import User    
class CustomJWTAuthentication(BaseAuthentication):
    """
    Custom authentication class to validate JWT tokens.
    """
    def authenticate(self, request):
        # Get the Authorization header
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            raise AuthenticationFailed('Authorization header is missing')

        try:
            # Extract the token from the header
            token = auth_header.split(' ')[1]
            # Decode the token using the secret key
            decoded_payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])

            # Fetch the user from the database using the user_id in the token payload
            user = User.objects.get(userid=decoded_payload['user_id'])
            return (user, None)
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Token has expired')
        except jwt.InvalidTokenError:
            raise AuthenticationFailed('Invalid token')
        except User.DoesNotExist:
            raise AuthenticationFailed('User not found')

        return None   
    
from django.contrib.auth.models import AnonymousUser
from urllib.parse import parse_qs
from channels.middleware import BaseMiddleware
import logging

logger = logging.getLogger(__name__)
class WebSocketJWTAuthenticationMiddleware(BaseMiddleware):
    """
    Custom middleware to authenticate WebSocket connections using a JWT token.
    """
    async def __call__(self, scope, receive, send):
        # Extract the token from the query string
        query_string = parse_qs(scope["query_string"].decode())
        token = query_string.get("token", [None])[0]

        if token:
            try:
                # Decode the token using the secret key
                decoded_payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])

                # Fetch the user from the database using the user_id in the token payload
                user = await User.objects.filter(userid=decoded_payload['user_id']).afirst()
                scope["user"] = user if user else AnonymousUser()
            except jwt.ExpiredSignatureError:
                logger.error("WebSocket token has expired.")
                scope["user"] = AnonymousUser()
            except jwt.InvalidTokenError:
                logger.error("WebSocket token is invalid.")
                scope["user"] = AnonymousUser()
            except User.DoesNotExist:
                logger.error("User not found for WebSocket token.")
                scope["user"] = AnonymousUser()
        else:
            logger.error("No token provided in WebSocket connection.")
            scope["user"] = AnonymousUser()

        return await super().__call__(scope, receive, send)

# Wrapper for middleware stack
def WebSocketJWTAuthMiddlewareStack(inner):
    return WebSocketJWTAuthenticationMiddleware(inner)

class WebSocketJWTAuthMiddlewareStack(BaseMiddleware):
    async def __call__(self, scope, receive, send):
        query_string = scope['query_string'].decode()
        query_params = parse_qs(query_string)
        token = query_params.get('token', [None])[0]

        if token:
            try:
                decoded_data = jwt.decode(token, options={"verify_signature": False})
                user_id = decoded_data.get('user_id')

                # Delay the import of User
                from login_app.models import User
                scope['user'] = await self.get_user(user_id)
            except Exception:
                scope['user'] = AnonymousUser()
        else:
            scope['user'] = AnonymousUser()

        return await super().__call__(scope, receive, send)

    @staticmethod
    async def get_user(user_id):
        from login_app.models import User  # Import here to avoid early settings access
        return await User.objects.get(id=user_id)