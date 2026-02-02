# login_app/views.py

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import User,Message
from .serializers import UserSerializer,MessageSerializer
from django.shortcuts import render, redirect
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import LoginSerializer
import pandas as pd
import matplotlib.pyplot as plt
import io
import base64
from uuid import uuid4
import codecs
from rest_framework.permissions import IsAuthenticated
from .middleware import CustomJWTAuthentication
class CreateOrUpdateUser(APIView):
    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response({"error": "Email is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email=email)
            serializer = UserSerializer(user, data=request.data)
        except User.DoesNotExist:
            serializer = UserSerializer(data=request.data)

        if serializer.is_valid():
            serializer.save()
            return Response({"message": "User created/updated successfully"}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

import jwt
from datetime import datetime, timedelta
from django.conf import settings

def generate_custom_jwt_tokens(user):
    """
    Generate custom access and refresh tokens for a given user.
    """
    # Define the payload for the access token
    access_payload = {
        'user_id': user.userid,  # Use your custom user ID field
        'email': user.email,
        'exp': datetime.utcnow() + timedelta(minutes=15),  # Access token expires in 15 minutes
        'iat': datetime.utcnow(),
    }

    # Define the payload for the refresh token
    refresh_payload = {
        'user_id': user.userid,  # Use your custom user ID field
        'email': user.email,
        'exp': datetime.utcnow() + timedelta(days=7),  # Refresh token expires in 7 days
        'iat': datetime.utcnow(),
    }

    # Generate the tokens using the secret key
    access_token = jwt.encode(access_payload, settings.SECRET_KEY, algorithm='HS256')
    refresh_token = jwt.encode(refresh_payload, settings.SECRET_KEY, algorithm='HS256')

    return {
        'access': access_token,
        'refresh': refresh_token,
    }
from django.shortcuts import render
class LoginPageView(APIView):
    def get(self, request):
        return render(request, 'login.html')
from django.utils.timezone import now
class LoginUser(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            # Validate user credentials
            validated_data = serializer.validated_data
            email = validated_data['email']
            user = User.objects.get(email=email)

            # Update the last_login field with the current timestamp
            user.last_login = now()
            user.save()

            # Generate JWT tokens
            tokens = generate_custom_jwt_tokens(user)

            # Return tokens and user info to the frontend
            return Response({
                'status': True,
                'message': 'Login successful',
                'userinfo': {
                    'userid': user.userid,
                    'email': user.email,
                    'name': user.name,
                    'role': user.role,
                },
                'access': tokens['access'],
                'refresh': tokens['refresh'],
            }, status=status.HTTP_200_OK)

        # If validation fails, return the errors
        return Response({
            'status': False,
            'message': 'Login failed',
            'errors': serializer.errors,
        }, status=status.HTTP_400_BAD_REQUEST)
class WelcomePageView(APIView):
    #authentication_classes = [TokenAuthentication]
    #permission_classes = [IsAuthenticated]

    def get(self, request):
        return render(request, 'welcome.html')    
    
# filepath: c:\Users\Ashutosh\Ashutosh_dashbord\admin\login_app\views.py

from rest_framework.parsers import MultiPartParser
from django.http import FileResponse
import codecs
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from django.shortcuts import render

import pandas as pd
import plotly.express as px
import io
import codecs
from rest_framework.parsers import MultiPartParser
from rest_framework.views import APIView
from django.shortcuts import render
class SalesPlotView(APIView):
    parser_classes = [MultiPartParser]

    def get(self, request, *args, **kwargs):
        return render(request, 'sales.html')

    def post(self, request, *args, **kwargs):
        file_obj = request.FILES.get('file')
        if not file_obj:
            return render(request, 'sales.html', {'error': 'CSV file is required'})

        try:
            # Read the uploaded file
            decoded_file = codecs.iterdecode(file_obj, 'latin1')
            df = pd.read_csv(io.StringIO(''.join(decoded_file)))
            df = df.fillna(0)

            # Validate the file content
            required_columns = ['PRODUCTLINE', 'SALES', 'YEAR_ID', 'QUANTITYORDERED', 'COUNTRY', 'CITY', 'STATE']
            if not all(column in df.columns for column in required_columns):
                return render(request, 'sales.html', {'error': f'The file must contain the following columns: {", ".join(required_columns)}'})

            # Calculate total sales and total quantity ordered
            total_sales = df['SALES'].sum()
            total_quantity_ordered = df['QUANTITYORDERED'].sum()

            # Generate the plot for product-wise sales
            product_sales = df.groupby('PRODUCTLINE')['SALES'].sum().reset_index()
            product_sales_fig = px.bar(product_sales,
                                       x='PRODUCTLINE',
                                       y='SALES',
                                       title='Product-wise Sales',
                                       labels={'PRODUCTLINE': 'Product Line', 'SALES': 'Total Sales'},
                                       hover_data={'SALES': True})
            product_sales_fig.update_layout(showlegend=False)
            product_sales_chart_html = product_sales_fig.to_html(full_html=False)

            # Generate the plot for year-wise sales
            year_sales = df.groupby('YEAR_ID')['SALES'].sum().reset_index()
            year_sales_fig = px.bar(year_sales,
                                    x='YEAR_ID',
                                    y='SALES',
                                    title='Year-wise Sales',
                                    labels={'YEAR_ID': 'Year', 'SALES': 'Total Sales'},
                                    hover_data={'SALES': True})
            year_sales_fig.update_layout(showlegend=False)
            year_sales_chart_html = year_sales_fig.to_html(full_html=False)

            # Generate the plot for state-wise sales filtered by country
            state_sales = df.groupby(['COUNTRY', 'STATE'])['SALES'].sum().reset_index()
            state_sales_fig = px.bar(state_sales,
                                     x='STATE',
                                     y='SALES',
                                     color='COUNTRY',
                                     title='State-wise Sales (Filtered by Country)',
                                     labels={'STATE': 'State', 'SALES': 'Total Sales', 'COUNTRY': 'Country'},
                                     hover_data={'SALES': True})
            state_sales_fig.update_layout(showlegend=True)
            state_sales_chart_html = state_sales_fig.to_html(full_html=False)

            # Generate the plot for country-wise sales
            country_sales = df.groupby('COUNTRY')['SALES'].sum().reset_index()
            country_sales_fig = px.bar(country_sales,
                                       x='COUNTRY',
                                       y='SALES',
                                       title='Country-wise Sales',
                                       labels={'COUNTRY': 'Country', 'SALES': 'Total Sales'},
                                       hover_data={'SALES': True})
            country_sales_fig.update_layout(showlegend=False)
            country_sales_chart_html = country_sales_fig.to_html(full_html=False)

            # Generate the line chart for product sales year-wise
            product_year_sales = df.groupby(['YEAR_ID', 'PRODUCTLINE'])['SALES'].sum().reset_index()
            product_year_fig = px.line(product_year_sales,
                                       x='YEAR_ID',
                                       y='SALES',
                                       color='PRODUCTLINE',
                                       title='Product Sales Analysis Year-wise',
                                       labels={'YEAR_ID': 'Year', 'SALES': 'Total Sales', 'PRODUCTLINE': 'Product Line'})
            product_year_fig.update_layout(showlegend=True)
            product_year_chart_html = product_year_fig.to_html(full_html=False)

            # Pass the calculated data and charts to the template
            return render(request, 'sales.html', {
                'total_sales': total_sales,
                'total_quantity_ordered': total_quantity_ordered,
                'product_sales_chart_html': product_sales_chart_html,
                'year_sales_chart_html': year_sales_chart_html,
                'state_sales_chart_html': state_sales_chart_html,
                'country_sales_chart_html': country_sales_chart_html,
                'product_year_chart_html': product_year_chart_html,
            })

        except Exception as e:
            return render(request, 'sales.html', {'error': str(e)})
        

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.utils.timezone import now

class MessageView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [CustomJWTAuthentication]

    def post(self, request):
        try:
            data = request.data
            from_user = data['from_user']
            to_user = data['to_user']
            message_text = data['message']

            # Update the last_login field for the sender
            User.objects.filter(userid=from_user).update(last_login=now())

            # Create the message
            message = Message.objects.create(
                from_user=from_user,
                to_user=to_user,
                message=message_text,
                session_id=data.get('session_id', uuid4())
            )

            return Response({
                'status': 'success',
                'message': 'Message sent successfully',
                'data': {
                    'from_user': message.from_user,
                    'to_user': message.to_user,
                    'message': message.message,
                    'created_date': message.created_date,
                }
            }, status=200)
        except Exception as e:
            return Response({'error': str(e)}, status=400)
from django.db.models import Count
class TopUsersView(APIView):
    authentication_classes = [CustomJWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # Get the top 10 users from the User table
        top_users = User.objects.all()[:10]
        top_users_data = [
            {
                'userid': user.userid,
                'name': user.name,
                'email': user.email,
            }
            for user in top_users
        ]

        # Search users by name if a query parameter is provided
        search_query = request.GET.get('search', None)
        if search_query:
            searched_users = User.objects.filter(name__icontains=search_query)
            searched_users_data = [
                {
                    'userid': user.userid,
                    'name': user.name,
                    'email': user.email,
                }
                for user in searched_users
            ]
            return Response({'searched_users': searched_users_data}, status=status.HTTP_200_OK)

        return Response({'top_users': top_users_data}, status=status.HTTP_200_OK)
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import TokenAuthentication
class UserInfoView(APIView):
    authentication_classes = [CustomJWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        print(f"Authorization header: {request.headers.get('Authorization')}")
        print(f"Authenticated user: {request.user}")

        if not request.user.is_authenticated:
            return Response({'error': 'User not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

        userinfo = {
            'userid': request.user.userid,
            'email': request.user.email,
            'name': request.user.name,
            'role': request.user.role,
        }
        return Response(userinfo, status=status.HTTP_200_OK)
from rest_framework.pagination import PageNumberPagination
    
class MessagePagination(PageNumberPagination):
    page_size = 10  # Number of messages per page    
class ReceivedMessagesView(APIView):
    authentication_classes = [CustomJWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            user_id = request.user.userid
            received_messages = Message.objects.filter(to_user=user_id).order_by('-created_date')
            paginator = MessagePagination()
            paginated_messages = paginator.paginate_queryset(received_messages, request)
            serializer = MessageSerializer(paginated_messages, many=True)
            return paginator.get_paginated_response(serializer.data)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        

from django.utils.timezone import now, timedelta
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .models import User

class UserStatusView(APIView):
    authentication_classes = [CustomJWTAuthentication]  # Add your authentication classes here
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            # Define the threshold for online status (e.g., 5 minutes)
            online_threshold = now() - timedelta(minutes=5)

            # Get all users and their online/offline status
            users = User.objects.all()
            
            user_status = [
                {
                    'userid': user.userid,
                    'name': user.name,
                    'is_online': user.last_login and user.last_login >= online_threshold
                }
                for user in users
            ]

            return Response(user_status, status=200)
        except Exception as e:
            return Response({'error': str(e)}, status=400) 


class MessageView(APIView):
    permission_classes = [IsAuthenticated]
    authentication_classes = [CustomJWTAuthentication] 
    def post(self, request):
        try:
            data = request.data
            from_user = data['from_user']
            to_user = data['to_user']
            message_text = data['message']

            # Update the last_login field for the sender
            User.objects.filter(userid=from_user).update(last_login=now())

            # Create the message
            message = Message.objects.create(
                from_user=from_user,
                to_user=to_user,
                message=message_text,
                session_id=data.get('session_id', uuid4())
            )

            # Broadcast the message to the WebSocket group
            channel_layer = get_channel_layer()
            async_to_sync(channel_layer.group_send)(
                f"received_messages_{to_user}",
                {
                    'type': 'send_message',
                    'from_user': message.from_user,
                    'to_user': message.to_user,
                    'message': message.message,
                    'created_date': str(message.created_date),
                }
            )

            return Response({
                'status': 'success',
                'message': 'Message sent successfully',
                'data': {
                    'from_user': message.from_user,
                    'to_user': message.to_user,
                    'message': message.message,
                    'created_date': message.created_date,
                }
            }, status=200)
        except Exception as e:
            return Response({'error': str(e)}, status=400)              