import os
from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from login_app.routing import websocket_urlpatterns
from login_app.middleware import WebSocketJWTAuthMiddlewareStack
from admin.middleware import TokenAuthMiddleware

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'admin.settings')

application = ProtocolTypeRouter({
    "http": get_asgi_application(),
    "websocket": TokenAuthMiddleware(
        WebSocketJWTAuthMiddlewareStack(
            URLRouter(websocket_urlpatterns)
        )
    ),
})