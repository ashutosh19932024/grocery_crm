from channels.middleware import BaseMiddleware
from django.contrib.auth.models import AnonymousUser
from urllib.parse import parse_qs
import jwt

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