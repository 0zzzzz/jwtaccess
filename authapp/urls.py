from django.urls import path
from authapp import views as authapp

app_name = 'authapp'


urlpatterns = [
    path('api/user_create/', authapp.UserCreateAPIView.as_view(), name='api_user_create'),
    path('api/user_update/<int:pk>/', authapp.UserUpdateAPIView.as_view(), name='api_user_update'),
]

