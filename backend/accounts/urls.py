from django.urls import path
from .views import (
    WebRegisterView, WebLoginView, WebLogoutView,
    RegisterAPIView, LoginAPIView, LogoutAPIView, UserMeAPIView
)

urlpatterns = [
    # Web UI Routes (supports both /accounts/* and root /*)
    path('login/', WebLoginView.as_view(), name='login'),
    path('register/', WebRegisterView.as_view(), name='register'),
    path('logout/', WebLogoutView.as_view(), name='logout'),
    path('accounts/login/', WebLoginView.as_view(), name='accounts_login'),
    path('accounts/register/', WebRegisterView.as_view(), name='accounts_register'),
    path('accounts/logout/', WebLogoutView.as_view(), name='accounts_logout'),

    # API Auth Routes
    path('api/v1/auth/register/', RegisterAPIView.as_view(), name='api-auth-register'),
    path('api/v1/auth/login/', LoginAPIView.as_view(), name='api-auth-login'),
    path('api/v1/auth/logout/', LogoutAPIView.as_view(), name='api-auth-logout'),
    path('api/v1/auth/me/', UserMeAPIView.as_view(), name='api-auth-me'),
]
