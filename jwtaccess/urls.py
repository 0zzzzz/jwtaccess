from django.contrib import admin
from django.urls import path, include
from jwtapp.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenBlacklistView,
    RotatedRefreshTokenView,
)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('auth/', include('authapp.urls', namespace='auth')),
    # JWT tokens
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/rotated/', RotatedRefreshTokenView.as_view(), name='token_rotated'),
]
