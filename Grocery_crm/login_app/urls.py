# login_app/urls.py

from django.urls import path, include
from .views import CreateOrUpdateUser
from .views import LoginPageView ,LoginUser, WelcomePageView,SalesPlotView,MessageView,TopUsersView,UserInfoView,ReceivedMessagesView,UserStatusView

urlpatterns = [
    path('user/', CreateOrUpdateUser.as_view(), name='create_update_user'),
    path('login_user/', LoginUser.as_view(), name='user_login'),
    path('', LoginPageView.as_view(), name='login_page'),
    path('welcome/', WelcomePageView.as_view(), name='welcome_page'), 
    path('sales/', SalesPlotView.as_view(), name='sales_page'),
    path('plot-sales/', SalesPlotView.as_view(), name='plot-sales'),
    path('api/message/', MessageView.as_view(), name='message_api'),
    path('api/top-users/', TopUsersView.as_view(), name='top_users_api'),
    path('api/userinfo/', UserInfoView.as_view(), name='userinfo_api'),
    path('api/received-messages/', ReceivedMessagesView.as_view(), name='received-messages'),
    path('api/user-status/', UserStatusView.as_view(), name='user-status'),
]
