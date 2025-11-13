"""
Unit tests for user authentication and management.
"""

import pytest
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient
from django.utils import timezone
from datetime import timedelta

from users.models import User, StudentProfile, OTPVerification, LoginHistory
from users.utils import create_otp, verify_otp


@pytest.fixture
def api_client():
    """Return API client."""
    return APIClient()


@pytest.fixture
def student_data():
    """Sample student registration data."""
    return {
        "email": "test@example.com",
        "phone": "+911234567890",
        "role": "STUDENT",
        "password": "TestPass123!",
        "password_confirm": "TestPass123!",
        "profile_data": {
            "full_name": "Test Student",
            "highest_qualification": "UNDERGRADUATE",
            "skills": "Python, Django",
            "city": "Mumbai"
        }
    }


@pytest.fixture
def create_student_user(db):
    """Create a verified student user."""
    user = User.objects.create_user(
        email="student@test.com",
        phone="+919876543210",
        role="STUDENT",
        password="TestPass123!",
        is_verified=True,
        status="ACTIVE"
    )
    StudentProfile.objects.create(
        user=user,
        full_name="Test Student",
        education_level="UNDERGRADUATE",
        skills="Python",
        city="Delhi"
    )
    return user


@pytest.fixture
def create_admin_user(db):
    """Create an admin user."""
    from users.models import AdminProfile
    user = User.objects.create_user(
        email="admin@test.com",
        phone="+919999999999",
        role="ADMIN",
        password="AdminPass123!",
        is_verified=True,
        is_staff=True,
        status="ACTIVE"
    )
    AdminProfile.objects.create(
        user=user,
        username="testadmin",
        full_name="Test Admin"
    )
    return user


class TestUserRegistration:
    """Test user registration."""
    
    @pytest.mark.django_db
    def test_register_student_success(self, api_client, student_data):
        """Test successful student registration."""
        url = reverse('register')
        response = api_client.post(url, student_data, format='json')
        
        assert response.status_code == status.HTTP_201_CREATED
        assert response.data['success'] is True
        assert 'user_id' in response.data['data']
        
        # Verify user created
        user = User.objects.get(email=student_data['email'])
        assert user.role == 'STUDENT'
        assert user.is_verified is False  # Not verified yet
        
        # Verify profile created
        assert hasattr(user, 'student_profile')
        assert user.student_profile.full_name == "Test Student"
    
    @pytest.mark.django_db
    def test_register_duplicate_email(self, api_client, student_data, create_student_user):
        """Test registration with duplicate email."""
        student_data['email'] = create_student_user.email
        url = reverse('register')
        response = api_client.post(url, student_data, format='json')
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST
    
    @pytest.mark.django_db
    def test_register_password_mismatch(self, api_client, student_data):
        """Test registration with mismatched passwords."""
        student_data['password_confirm'] = "DifferentPass123!"
        url = reverse('register')
        response = api_client.post(url, student_data, format='json')
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert 'password' in str(response.data).lower()


class TestOTPVerification:
    """Test OTP verification."""
    
    @pytest.mark.django_db
    def test_create_otp(self):
        """Test OTP creation."""
        identifier = "test@example.com"
        otp = create_otp(identifier, 'REGISTRATION')
        
        assert otp is not None
        assert otp.email == identifier
        assert len(otp.otp_code) == 6
        assert otp.is_verified is False
    
    @pytest.mark.django_db
    def test_verify_otp_success(self):
        """Test successful OTP verification."""
        identifier = "test@example.com"
        otp = create_otp(identifier, 'REGISTRATION')
        
        success, message, verified_otp = verify_otp(
            identifier, 
            otp.otp_code, 
            'REGISTRATION'
        )
        
        assert success is True
        assert verified_otp.is_verified is True
    
    @pytest.mark.django_db
    def test_verify_otp_invalid_code(self):
        """Test OTP verification with invalid code."""
        identifier = "test@example.com"
        create_otp(identifier, 'REGISTRATION')
        
        success, message, _ = verify_otp(
            identifier, 
            "000000",  # Wrong OTP
            'REGISTRATION'
        )
        
        assert success is False
        assert "Invalid OTP" in message
    
    @pytest.mark.django_db
    def test_verify_otp_expired(self):
        """Test OTP verification with expired OTP."""
        identifier = "test@example.com"
        otp = create_otp(identifier, 'REGISTRATION')
        
        # Manually expire the OTP
        otp.expires_at = timezone.now() - timedelta(minutes=5)
        otp.save()
        
        success, message, _ = verify_otp(
            identifier, 
            otp.otp_code, 
            'REGISTRATION'
        )
        
        assert success is False
        assert "expired" in message.lower()
    
    @pytest.mark.django_db
    def test_otp_verification_endpoint(self, api_client, create_student_user):
        """Test OTP verification API endpoint."""
        otp = create_otp(create_student_user.email, 'LOGIN', create_student_user)
        
        url = reverse('verify-otp')
        data = {
            "identifier": create_student_user.email,
            "otp_code": otp.otp_code,
            "purpose": "LOGIN"
        }
        
        response = api_client.post(url, data, format='json')
        
        assert response.status_code == status.HTTP_200_OK
        assert response.data['success'] is True


class TestLogin:
    """Test login functionality."""
    
    @pytest.mark.django_db
    def test_login_success(self, api_client, create_student_user):
        """Test successful login with password."""
        url = reverse('login')
        data = {
            "identifier": create_student_user.email,
            "password": "TestPass123!"
        }
        
        response = api_client.post(url, data, format='json')
        
        assert response.status_code == status.HTTP_200_OK
        assert response.data['success'] is True
        assert 'access' in response.data['data']
        assert 'refresh' in response.data['data']
        assert 'user' in response.data['data']
    
    @pytest.mark.django_db
    def test_login_invalid_credentials(self, api_client, create_student_user):
        """Test login with invalid credentials."""
        url = reverse('login')
        data = {
            "identifier": create_student_user.email,
            "password": "WrongPassword123!"
        }
        
        response = api_client.post(url, data, format='json')
        
        assert response.status_code == status.HTTP_400_BAD_REQUEST
    
    @pytest.mark.django_db
    def test_login_unverified_user(self, api_client, db):
        """Test login with unverified user."""
        user = User.objects.create_user(
            email="unverified@test.com",
            phone="+919999999998",
            role="STUDENT",
            password="TestPass123!",
            is_verified=False
        )
        
        url = reverse('login')
        data = {
            "identifier": user.email,
            "password": "TestPass123!"
        }
        
        response = api_client.post(url, data, format='json')
        
        assert response.status_code == status.HTTP_403_FORBIDDEN
        assert "verify" in response.data['message'].lower()
    
    @pytest.mark.django_db
    def test_otp_login_flow(self, api_client, create_student_user):
        """Test OTP login flow."""
        url = reverse('login-otp')
        
        # Step 1: Request OTP
        data = {"identifier": create_student_user.email}
        response = api_client.post(url, data, format='json')
        
        assert response.status_code == status.HTTP_200_OK
        
        # Get the OTP from database
        otp = OTPVerification.objects.filter(
            email=create_student_user.email,
            purpose='LOGIN'
        ).order_by('-created_at').first()
        
        assert otp is not None
        
        # Step 2: Login with OTP
        data = {
            "identifier": create_student_user.email,
            "otp_code": otp.otp_code
        }
        response = api_client.post(url, data, format='json')
        
        assert response.status_code == status.HTTP_200_OK
        assert 'access' in response.data['data']


class TestPasswordReset:
    """Test password reset functionality."""
    
    @pytest.mark.django_db
    def test_forgot_password(self, api_client, create_student_user):
        """Test forgot password request."""
        url = reverse('forgot-password')
        data = {"identifier": create_student_user.email}
        
        response = api_client.post(url, data, format='json')
        
        assert response.status_code == status.HTTP_200_OK
        
        # Verify OTP created
        otp = OTPVerification.objects.filter(
            email=create_student_user.email,
            purpose='PASSWORD_RESET'
        ).order_by('-created_at').first()
        
        assert otp is not None
    
    @pytest.mark.django_db
    def test_reset_password_success(self, api_client, create_student_user):
        """Test successful password reset."""
        # Create OTP
        otp = create_otp(
            create_student_user.email, 
            'PASSWORD_RESET', 
            create_student_user
        )
        
        url = reverse('reset-password')
        data = {
            "identifier": create_student_user.email,
            "otp_code": otp.otp_code,
            "new_password": "NewSecurePass123!",
            "new_password_confirm": "NewSecurePass123!"
        }
        
        response = api_client.post(url, data, format='json')
        
        assert response.status_code == status.HTTP_200_OK
        
        # Verify password changed
        create_student_user.refresh_from_db()
        assert create_student_user.check_password("NewSecurePass123!")


class TestProfile:
    """Test profile management."""
    
    @pytest.mark.django_db
    def test_get_profile(self, api_client, create_student_user):
        """Test getting user profile."""
        api_client.force_authenticate(user=create_student_user)
        
        url = reverse('profile')
        response = api_client.get(url)
        
        assert response.status_code == status.HTTP_200_OK
        assert response.data['data']['email'] == create_student_user.email
        assert 'profile' in response.data['data']
    
    @pytest.mark.django_db
    def test_update_profile(self, api_client, create_student_user):
        """Test updating user profile."""
        api_client.force_authenticate(user=create_student_user)
        
        url = reverse('profile')
        data = {
            "profile_data": {
                "full_name": "Updated Name",
                "city": "Bangalore"
            }
        }
        
        response = api_client.put(url, data, format='json')
        
        assert response.status_code == status.HTTP_200_OK
        
        # Verify profile updated
        create_student_user.refresh_from_db()
        assert create_student_user.student_profile.full_name == "Updated Name"
        assert create_student_user.student_profile.city == "Bangalore"


class TestLogout:
    """Test logout functionality."""
    
    @pytest.mark.django_db
    def test_logout(self, api_client, create_student_user):
        """Test logout."""
        api_client.force_authenticate(user=create_student_user)
        
        # Get tokens
        from rest_framework_simplejwt.tokens import RefreshToken
        refresh = RefreshToken.for_user(create_student_user)
        
        url = reverse('logout')
        data = {"refresh": str(refresh)}
        
        response = api_client.post(url, data, format='json')
        
        assert response.status_code == status.HTTP_200_OK


class TestAdminViews:
    """Test admin views."""
    
    @pytest.mark.django_db
    def test_list_users_admin(self, api_client, create_admin_user, create_student_user):
        """Test admin can list users."""
        api_client.force_authenticate(user=create_admin_user)
        
        url = reverse('user-list')
        response = api_client.get(url)
        
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data['results']) >= 2  # Admin + Student
    
    @pytest.mark.django_db
    def test_list_users_non_admin(self, api_client, create_student_user):
        """Test non-admin cannot list users."""
        api_client.force_authenticate(user=create_student_user)
        
        url = reverse('user-list')
        response = api_client.get(url)
        
        assert response.status_code == status.HTTP_403_FORBIDDEN
    
    @pytest.mark.django_db
    def test_update_user_status(self, api_client, create_admin_user, create_student_user):
        """Test admin can update user status."""
        api_client.force_authenticate(user=create_admin_user)
        
        url = reverse('user-status-update', kwargs={'user_id': create_student_user.id})
        data = {
            "status": "SUSPENDED",
            "is_active": False,
            "reason": "Test suspension"
        }
        
        response = api_client.patch(url, data, format='json')
        
        assert response.status_code == status.HTTP_200_OK
        
        # Verify status updated
        create_student_user.refresh_from_db()
        assert create_student_user.status == "SUSPENDED"
        assert create_student_user.is_active is False


class TestLoginHistory:
    """Test login history tracking."""
    
    @pytest.mark.django_db
    def test_login_history_created(self, api_client, create_student_user):
        """Test login history is created on login."""
        url = reverse('login')
        data = {
            "identifier": create_student_user.email,
            "password": "TestPass123!"
        }
        
        response = api_client.post(url, data, format='json')
        
        assert response.status_code == status.HTTP_200_OK
        
        # Verify login history created
        history = LoginHistory.objects.filter(user=create_student_user).first()
        assert history is not None
        assert history.success is True
    
    @pytest.mark.django_db
    def test_get_login_history(self, api_client, create_student_user):
        """Test getting login history."""
        # Create login history
        LoginHistory.objects.create(
            user=create_student_user,
            ip_address="127.0.0.1",
            user_agent="Test Agent",
            login_method="PASSWORD",
            success=True
        )
        
        api_client.force_authenticate(user=create_student_user)
        
        url = reverse('login-history')
        response = api_client.get(url)
        
        assert response.status_code == status.HTTP_200_OK
        assert len(response.data['results']) >= 1
