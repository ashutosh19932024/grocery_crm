from django.urls import path
from .consumers import MessageConsumer,UserStatusConsumer, ReceivedMessagesConsumer

websocket_urlpatterns = [
    path('ws/messages/<str:userid>/', MessageConsumer.as_asgi()),
    path('ws/user-status/', UserStatusConsumer.as_asgi()),
    path('ws/received-messages/', ReceivedMessagesConsumer.as_asgi()),
]