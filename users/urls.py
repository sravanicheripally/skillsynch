"""
URL Configuration for users app.
"""

from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView

from .views import (
    # Registration and Verification
    UserRegistrationView,
    OTPVerificationView,
    ResendOTPView,
    
    # Login
    LoginView,
    OTPLoginView,
    
    # Password Reset
    ForgotPasswordView,
    ResetPasswordView,
    
    # Profile
    ProfileView,
    
    # Logout
    LogoutView,
    LogoutAllView,
    
    # Admin
    UserListView,
    UserStatusUpdateView,
    
    # Login History
    LoginHistoryView,
)

urlpatterns = [
    # Registration and Verification
    path('register/', UserRegistrationView.as_view(), name='register'),
    path('verify-otp/', OTPVerificationView.as_view(), name='verify-otp'),
    path('resend-otp/', ResendOTPView.as_view(), name='resend-otp'),
    
    # Login
    path('login/', LoginView.as_view(), name='login'),
    path('login-otp/', OTPLoginView.as_view(), name='login-otp'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token-refresh'),
    
    # Password Reset
    path('forgot-password/', ForgotPasswordView.as_view(), name='forgot-password'),
    path('reset-password/', ResetPasswordView.as_view(), name='reset-password'),
    
    # Profile
    path('profile/', ProfileView.as_view(), name='profile'),
    
    # Logout
    path('logout/', LogoutView.as_view(), name='logout'),
    path('logout-all/', LogoutAllView.as_view(), name='logout-all'),
    
    # Admin
    path('users/', UserListView.as_view(), name='user-list'),
    path('users/<uuid:user_id>/status/', UserStatusUpdateView.as_view(), name='user-status-update'),
    
    # Login History
    path('login-history/', LoginHistoryView.as_view(), name='login-history'),
]
