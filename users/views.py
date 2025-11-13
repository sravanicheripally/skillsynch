"""
Views for user authentication and management.
"""

import logging
from django.contrib.auth import authenticate
from django.utils import timezone
from rest_framework import status, generics
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.throttling import AnonRateThrottle, UserRateThrottle
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken, BlacklistedToken
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from institute.models import InstituteProfile

from .models import CompanyProfile, User, LoginHistory
from .serializers import (
    UserRegistrationSerializer, OTPVerificationSerializer, OTPRequestSerializer,
    LoginSerializer, OTPLoginSerializer, PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer, UserDetailSerializer, ProfileUpdateSerializer,
    UserListSerializer, UserStatusUpdateSerializer, LoginHistorySerializer
)
from .permissions import IsAdmin, IsSuperAdmin, IsActive
from .utils import (
    create_otp, verify_otp, can_resend_otp, get_client_ip,
    get_user_agent, get_device_info, success_response, error_response
)

logger = logging.getLogger(__name__)


class OTPThrottle(AnonRateThrottle):
    """Custom throttle for OTP requests."""
    rate = '5/hour'


class LoginThrottle(AnonRateThrottle):
    """Custom throttle for login requests."""
    rate = '10/hour'


# Registration and Verification Views
class UserRegistrationView(APIView):
    """
    User registration endpoint.
    Creates user and sends OTP for verification.
    """
    permission_classes = [AllowAny]
    throttle_classes = [AnonRateThrottle]
    
    @swagger_auto_schema(
        operation_description="""Register a new user with role-specific profile.
        
        Each role requires different profile_data fields:
        
        **STUDENT**: full_name, highest_qualification, skills, city, [resume, date_of_birth, bio,'gender',  
        'preferred_learning_mode','graduation_year','primary_skills_interested','agreed_to_terms'
                        ]
        **INSTITUTE**: institute_name, gst_number, address, [accreditation, logo, website]
        **COMPANY**: company_name, cin_number, industry, address, [company_size, website, logo]
        **MENTOR**: full_name, experience_years, expertise_areas, [linkedin_url, bio, hourly_rate]
        **NBFC**: organization_name, nbfc_license_number, contact_person, address
        **ADMIN**: username, full_name, [department, employee_id]
        """,
        request_body=UserRegistrationSerializer,
        responses={
            201: openapi.Response('User registered successfully', UserDetailSerializer),
            400: 'Bad Request'
        },
        examples={
            'application/json': {
                'STUDENT': {
                    'email': 'student@example.com',
                    'phone': '+919876543210',
                    'role': 'STUDENT',
                    'password': 'SecurePass123!',
                    'password_confirm': 'SecurePass123!',
                    'profile_data': {
                        'full_name': 'John Doe',
                        'highest_qualification': 'BACHELOR',
                        'skills': ['Python', 'Django'],
                        'city': 'Mumbai',
                        'bio': 'Aspiring software developer',
                        'gender':"FEMALE",
                        'preferred_learning_mode':"online",
                        'graduation_year':2022,
                        'primary_skills_interested':'python ,django',
                        'agreed_to_terms':True,
                        
                    }
                },
                'COMPANY': {
                    'email': 'hr@company.com',
                    'phone': '+919876543211',
                    'role': 'COMPANY',
                    'password': 'SecurePass123!',
                    'password_confirm': 'SecurePass123!',
                    'profile_data': {
                        'company_name': 'Tech Corp',
                        'cin_number': 'U12345MH2020PTC123456',
                        'industry': 'IT',
                        'company_size': '50-200',
                        'address': '123 Business St, Mumbai',
                        'website': 'https://techcorp.com'
                    }
                },
                'INSTITUTE': {
                    'email': 'admin@institute.edu',
                    'phone': '+919876543212',
                    'role': 'INSTITUTE',
                    'password': 'SecurePass123!',
                    'password_confirm': 'SecurePass123!',
                    'profile_data': {
                        'institute_name': 'ABC Institute of Technology',
                        'gst_number': '27AABCT1234A1Z5',
                        'address': '456 Education Lane, Delhi',
                        'accreditation': 'NAAC A+',
                        'established_year': 1990
                    }
                }
            }
        }
    )
    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        
        if not serializer.is_valid():
            return error_response(
                message="Validation failed",
                errors=serializer.errors,
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            user = serializer.save()
            
            # Generate OTP for email verification
            otp_email = create_otp(user.email, 'REGISTRATION', user)
            logger.info(f"Created OTP for email: {user.email}, OTP: {otp_email.otp_code}")
            
            # Explicitly send email (in addition to signal)
            from .utils import send_otp_email
            email_sent = send_otp_email(user.email, otp_email.otp_code, 'REGISTRATION')
            logger.info(f"Email sent result: {email_sent}")
            
            # Generate OTP for phone verification
            otp_phone = create_otp(str(user.phone), 'REGISTRATION', user)
            logger.info(f"Created OTP for phone: {user.phone}, OTP: {otp_phone.otp_code}")
            
            # Explicitly send SMS (in addition to signal)
            from .utils import send_otp_sms
            sms_sent = send_otp_sms(str(user.phone), otp_phone.otp_code, 'REGISTRATION')
            logger.info(f"SMS sent result: {sms_sent}")
            
            return success_response(
                data={
                    'user_id': str(user.id),
                    'email': user.email,
                    'phone': str(user.phone),
                    'email_otp': otp_email.otp_code,  # For development/testing
                    'phone_otp': otp_phone.otp_code,  # For development/testing
                    'message': 'OTP sent to email and phone for verification'
                },
                message="User registered successfully. Please verify your email and phone.",
                status=status.HTTP_201_CREATED
            )
        
        except Exception as e:
            logger.error(f"Registration error: {str(e)}")
            import traceback
            logger.error(traceback.format_exc())
            return error_response(
                message="Registration failed",
                errors={'detail': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class OTPVerificationView(APIView):
    """
    OTP verification endpoint.
    Verifies OTP and activates user account.
    """
    permission_classes = [AllowAny]
    
    @swagger_auto_schema(
        operation_description="Verify OTP for registration, login, or password reset",
        request_body=OTPVerificationSerializer,
        responses={
            200: 'OTP verified successfully',
            400: 'Invalid OTP or verification failed'
        }
    )
    def post(self, request):
        serializer = OTPVerificationSerializer(data=request.data)
        
        if not serializer.is_valid():
            return error_response(
                message="Validation failed",
                errors=serializer.errors,
                status=status.HTTP_400_BAD_REQUEST
            )
        
        identifier = serializer.validated_data['identifier']
        otp_code = serializer.validated_data['otp_code']
        purpose = serializer.validated_data['purpose']
        
        # Verify OTP
        success, message, otp = verify_otp(identifier, otp_code, purpose)
        
        if not success:
            return error_response(message=message, status=status.HTTP_400_BAD_REQUEST)
        
        # If registration OTP, mark user as verified
        if purpose == 'REGISTRATION' and otp.user:
            user = otp.user
            
            # Check which was verified (email or phone)
            if otp.email:
                # Mark email as verified
                pass  # We'll use is_verified for overall verification
            
            if otp.phone:
                # Mark phone as verified
                pass
            
            # For simplicity, mark user as verified and active after any successful OTP
            if not user.is_verified:
                user.is_verified = True
                user.status = 'ACTIVE'
                user.save()
        
        return success_response(
            data={'verified': True},
            message=message,
            status=status.HTTP_200_OK
        )


class ResendOTPView(APIView):
    """
    Resend OTP endpoint with rate limiting.
    """
    permission_classes = [AllowAny]
    throttle_classes = []
    
    @swagger_auto_schema(
        operation_description="Resend OTP for verification",
        request_body=OTPRequestSerializer,
        responses={
            200: 'OTP sent successfully',
            400: 'Too many requests or invalid data'
        }
    )
    def post(self, request):
        serializer = OTPRequestSerializer(data=request.data)
        
        if not serializer.is_valid():
            return error_response(
                message="Validation failed",
                errors=serializer.errors,
                status=status.HTTP_400_BAD_REQUEST
            )
        
        identifier = serializer.validated_data['identifier']
        purpose = serializer.validated_data['purpose']
        
        # Check if OTP can be resent
        can_resend, message, wait_seconds = can_resend_otp(identifier, purpose)
        
        if not can_resend:
            return error_response(
                message=message,
                errors={'wait_seconds': wait_seconds},
                status=status.HTTP_429_TOO_MANY_REQUESTS
            )
        
        # Find user if exists
        user = None
        if '@' in identifier:
            try:
                user = User.objects.get(email=identifier)
            except User.DoesNotExist:
                pass
        else:
            try:
                user = User.objects.get(phone=identifier)
            except User.DoesNotExist:
                pass
        
        # Create and send new OTP
        try:
            otp = create_otp(identifier, purpose, user)
            return success_response(
                data={'message': 'OTP sent successfully'},
                message="OTP has been sent to your email/phone",
                status=status.HTTP_200_OK
            )
        except Exception as e:
            logger.error(f"Error resending OTP: {str(e)}")
            return error_response(
                message="Failed to send OTP",
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


# Login Views
class LoginView(APIView):
    """
    Login with email/phone + password.
    Returns JWT tokens.
    """
    permission_classes = [AllowAny]
    throttle_classes = []
    
    @swagger_auto_schema(
        operation_description="Login with email/phone and password",
        request_body=LoginSerializer,
        responses={
            200: openapi.Response('Login successful', openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'access': openapi.Schema(type=openapi.TYPE_STRING),
                    'refresh': openapi.Schema(type=openapi.TYPE_STRING),
                    'user': openapi.Schema(type=openapi.TYPE_OBJECT),
                }
            )),
            400: 'Invalid credentials'
        }
    )
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        
        if not serializer.is_valid():
            # Log failed login attempt
            self._log_login_attempt(request, None, False, "Invalid credentials")
            return error_response(
                message="Invalid credentials",
                errors=serializer.errors,
                status=status.HTTP_400_BAD_REQUEST
            )
        
        user = serializer.validated_data['user']
        
        # Check if user is verified
        if not user.is_verified:
            return error_response(
                message="Please verify your email/phone before logging in",
                status=status.HTTP_403_FORBIDDEN
            )
        
        # ✅ Additional Check: INSTITUTE must be approved by ADMIN
        institute_profile = InstituteProfile.objects.filter(user=user).first()
        if user.role == 'INSTITUTE': 
            if institute_profile.admin_approved == 'PENDING':
                return error_response(
                    message="Your institute account is under admin review. Approval pending.",
                    status=status.HTTP_403_FORBIDDEN
                )
            if user.status != 'ACTIVE':
                return error_response(
                    message="Your institute account is not active. Contact support.",
                    status=status.HTTP_403_FORBIDDEN
                )
        company_profile = CompanyProfile.objects.filter(user=user).first()
        if user.role == 'COMPANY': 
            if company_profile.admin_approved == 'PENDING':
                return error_response(
                    message="Your company account is under admin review. Approval pending.",
                    status=status.HTTP_403_FORBIDDEN
                )
            if user.status != 'ACTIVE':
                return error_response(
                    message="Your company account is not active. Contact support.",
                    status=status.HTTP_403_FORBIDDEN
                )

        
        # Generate JWT tokens
        refresh = RefreshToken.for_user(user)
        
        # Update last login
        user.last_login = timezone.now()
        user.save(update_fields=['last_login'])
        
        # Log successful login
        self._log_login_attempt(request, user, True, None)
        
        # Get user details
        user_data = UserDetailSerializer(user).data
        
        return success_response(
            data={
                'access': f"Bearer {str(refresh.access_token)}",
                'refresh': f"Bearer {str(refresh)}",
                'user': user_data
            },
            message="Login successful",
            status=status.HTTP_200_OK
        )
    
    def _log_login_attempt(self, request, user, success, failure_reason=None):
        """Log login attempt to LoginHistory."""
        try:
            LoginHistory.objects.create(
                user=user,
                ip_address=get_client_ip(request),
                user_agent=get_user_agent(request),
                device_info=get_device_info(request),
                login_method='PASSWORD',
                success=success,
                failure_reason=failure_reason or ''
            )
        except Exception as e:
            logger.error(f"Error logging login attempt: {str(e)}")


class OTPLoginView(APIView):
    """
    Login with OTP (passwordless).
    First request sends OTP, second request verifies and logs in.
    """
    permission_classes = [AllowAny]
    throttle_classes = [LoginThrottle]
    
    @swagger_auto_schema(
        operation_description="Request OTP for login or verify OTP to login",
        request_body=OTPLoginSerializer,
        responses={
            200: 'OTP sent or login successful',
            400: 'Invalid data or OTP'
        }
    )
    def post(self, request):
        identifier = request.data.get('identifier')
        otp_code = request.data.get('otp_code')
        
        if not identifier:
            return error_response(
                message="Identifier (email/phone) is required",
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # If OTP code provided, verify and login
        if otp_code:
            return self._verify_and_login(request, identifier, otp_code)
        
        # Otherwise, send OTP
        return self._send_login_otp(request, identifier)
    
    def _send_login_otp(self, request, identifier):
        """Send OTP for login."""
        # Find user
        user = None
        if '@' in identifier:
            try:
                user = User.objects.get(email=identifier)
            except User.DoesNotExist:
                return error_response(
                    message="User not found",
                    status=status.HTTP_404_NOT_FOUND
                )
        else:
            try:
                user = User.objects.get(phone=identifier)
            except User.DoesNotExist:
                return error_response(
                    message="User not found",
                    status=status.HTTP_404_NOT_FOUND
                )
        
        # Check if user is active
        if not user.is_active:
            return error_response(
                message="User account is disabled",
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Create and send OTP
        try:
            otp = create_otp(identifier, 'LOGIN', user)
            return success_response(
                data={'message': 'OTP sent successfully'},
                message="OTP has been sent to your email/phone",
                status=status.HTTP_200_OK
            )
        except Exception as e:
            logger.error(f"Error sending login OTP: {str(e)}")
            return error_response(
                message="Failed to send OTP",
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    def _verify_and_login(self, request, identifier, otp_code):
        """Verify OTP and login user."""
        # Verify OTP
        success, message, otp = verify_otp(identifier, otp_code, 'LOGIN')
        
        if not success or not otp.user:
            self._log_login_attempt(request, None, False, "Invalid OTP")
            return error_response(message=message, status=status.HTTP_400_BAD_REQUEST)
        
        user = otp.user
        
        # Generate JWT tokens
        refresh = RefreshToken.for_user(user)
        
        # Update last login
        user.last_login = timezone.now()
        user.save(update_fields=['last_login'])
        
        # Log successful login
        self._log_login_attempt(request, user, True, None)
        
        # Get user details
        user_data = UserDetailSerializer(user).data
        
        return success_response(
            data={
                'access': str(refresh.access_token),
                'refresh': str(refresh),
                'user': user_data
            },
            message="Login successful",
            status=status.HTTP_200_OK
        )
    
    def _log_login_attempt(self, request, user, success, failure_reason=None):
        """Log login attempt to LoginHistory."""
        try:
            LoginHistory.objects.create(
                user=user,
                ip_address=get_client_ip(request),
                user_agent=get_user_agent(request),
                device_info=get_device_info(request),
                login_method='OTP',
                success=success,
                failure_reason=failure_reason or ''
            )
        except Exception as e:
            logger.error(f"Error logging login attempt: {str(e)}")


# Password Reset Views
class ForgotPasswordView(APIView):
    """
    Request password reset OTP.
    """
    permission_classes = [AllowAny]
    throttle_classes = [OTPThrottle]
    
    @swagger_auto_schema(
        operation_description="Request password reset OTP",
        request_body=PasswordResetRequestSerializer,
        responses={
            200: 'OTP sent successfully',
            404: 'User not found'
        }
    )
    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        
        if not serializer.is_valid():
            return error_response(
                message="Validation failed",
                errors=serializer.errors,
                status=status.HTTP_400_BAD_REQUEST
            )
        
        identifier = serializer.validated_data['identifier']
        
        # Find user
        user = None
        if '@' in identifier:
            try:
                user = User.objects.get(email=identifier)
            except User.DoesNotExist:
                # Don't reveal if user exists or not
                return success_response(
                    data={'message': 'If the user exists, OTP has been sent'},
                    message="Password reset OTP sent",
                    status=status.HTTP_200_OK
                )
        else:
            try:
                user = User.objects.get(phone=identifier)
            except User.DoesNotExist:
                return success_response(
                    data={'message': 'If the user exists, OTP has been sent'},
                    message="Password reset OTP sent",
                    status=status.HTTP_200_OK
                )
        
        # Create and send OTP
        try:
            otp = create_otp(identifier, 'PASSWORD_RESET', user)
            return success_response(
                data={'message': 'OTP sent successfully'},
                message="Password reset OTP has been sent to your email/phone",
                status=status.HTTP_200_OK
            )
        except Exception as e:
            logger.error(f"Error sending password reset OTP: {str(e)}")
            return error_response(
                message="Failed to send OTP",
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class ResetPasswordView(APIView):
    """
    Reset password using OTP.
    """
    permission_classes = [AllowAny]
    
    @swagger_auto_schema(
        operation_description="Reset password using OTP",
        request_body=PasswordResetConfirmSerializer,
        responses={
            200: 'Password reset successful',
            400: 'Invalid OTP or data'
        }
    )
    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        
        if not serializer.is_valid():
            return error_response(
                message="Validation failed",
                errors=serializer.errors,
                status=status.HTTP_400_BAD_REQUEST
            )
        
        identifier = serializer.validated_data['identifier']
        otp = serializer.validated_data['otp']
        new_password = serializer.validated_data['new_password']
        
        # Verify OTP
        success, message, otp = verify_otp(identifier, otp, 'PASSWORD_RESET')
        
        if not success or not otp.user:
            return error_response(message=message, status=status.HTTP_400_BAD_REQUEST)
        
        # Reset password
        user = otp.user
        user.set_password(new_password)
        user.save()
        
        logger.info(f"Password reset successful for user: {user.email}")
        
        return success_response(
            data={'message': 'Password reset successful'},
            message="Your password has been reset successfully",
            status=status.HTTP_200_OK
        )


# Profile and User Management Views
class ProfileView(APIView):
    """
    Get and update user profile.
    """
    permission_classes = [IsAuthenticated]
    
    @swagger_auto_schema(
        operation_description="Get logged-in user profile",
        responses={
            200: UserDetailSerializer,
            401: 'Unauthorized'
        }
    )
    def get(self, request):
        """Get user profile."""
        serializer = UserDetailSerializer(request.user)
        return success_response(
            data=serializer.data,
            message="Profile retrieved successfully",
            status=status.HTTP_200_OK
        )
    
    @swagger_auto_schema(
        operation_description="Update user profile",
        request_body=ProfileUpdateSerializer,
        responses={
            200: UserDetailSerializer,
            400: 'Bad Request'
        }
    )
    def put(self, request):
        """Update user profile."""
        serializer = ProfileUpdateSerializer(
            data=request.data,
            context={'request': request}
        )
        
        if not serializer.is_valid():
            return error_response(
                message="Validation failed",
                errors=serializer.errors,
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            user = serializer.save()
            user_data = UserDetailSerializer(user).data
            
            return success_response(
                data=user_data,
                message="Profile updated successfully",
                status=status.HTTP_200_OK
            )
        except Exception as e:
            logger.error(f"Error updating profile: {str(e)}")
            return error_response(
                message="Failed to update profile",
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class LogoutView(APIView):
    """
    Logout current session (blacklist refresh token).
    """
    permission_classes = [IsAuthenticated]
    
    @swagger_auto_schema(
        operation_description="Logout from current session",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'refresh': openapi.Schema(type=openapi.TYPE_STRING, description='Refresh token')
            },
            required=['refresh']
        ),
        responses={
            200: 'Logout successful',
            400: 'Bad Request'
        }
    )
    def post(self, request):
        """Logout user."""
        try:
            refresh_token = request.data.get('refresh')
            
            if not refresh_token:
                return error_response(
                    message="Refresh token is required",
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Blacklist the refresh token
            token = RefreshToken(refresh_token)
            token.blacklist()
            
            # Update login history
            login_record = LoginHistory.objects.filter(
                user=request.user,
                logged_out_at__isnull=True
            ).order_by('-logged_in_at').first()
            
            if login_record:
                login_record.logged_out_at = timezone.now()
                login_record.save()
            
            return success_response(
                data={'message': 'Logged out successfully'},
                message="You have been logged out",
                status=status.HTTP_200_OK
            )
        
        except Exception as e:
            logger.error(f"Logout error: {str(e)}")
            return error_response(
                message="Logout failed",
                errors={'detail': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )


class LogoutAllView(APIView):
    """
    Logout from all devices (blacklist all refresh tokens).
    """
    permission_classes = [IsAuthenticated]
    
    @swagger_auto_schema(
        operation_description="Logout from all devices",
        responses={
            200: 'Logged out from all devices',
            500: 'Internal Server Error'
        }
    )
    def post(self, request):
        """Logout from all devices."""
        try:
            # Get all outstanding tokens for the user
            tokens = OutstandingToken.objects.filter(user=request.user)
            
            # Blacklist all tokens
            for token in tokens:
                try:
                    BlacklistedToken.objects.get_or_create(token=token)
                except:
                    pass
            
            # Update all login history records
            LoginHistory.objects.filter(
                user=request.user,
                logged_out_at__isnull=True
            ).update(logged_out_at=timezone.now())
            
            return success_response(
                data={'message': 'Logged out from all devices'},
                message="You have been logged out from all devices",
                status=status.HTTP_200_OK
            )
        
        except Exception as e:
            logger.error(f"Logout all error: {str(e)}")
            return error_response(
                message="Failed to logout from all devices",
                errors={'detail': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


# Admin Views
class UserListView(generics.ListAPIView):
    """
    List all users (Admin only).
    """
    queryset = User.objects.all()
    serializer_class = UserListSerializer
    permission_classes = [IsAuthenticated, IsAdmin]
    
    @swagger_auto_schema(
        operation_description="Get list of all users (Admin only)",
        responses={
            200: UserListSerializer(many=True),
            403: 'Forbidden'
        }
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)


class UserStatusUpdateView(APIView):
    """
    Update user status - activate/deactivate/suspend (Admin only).
    """
    permission_classes = [IsAuthenticated, IsAdmin]
    
    @swagger_auto_schema(
        operation_description="Update user status (Admin only)",
        request_body=UserStatusUpdateSerializer,
        responses={
            200: 'Status updated successfully',
            400: 'Bad Request',
            403: 'Forbidden',
            404: 'User not found'
        }
    )
    def patch(self, request, user_id):
        """Update user status."""
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return error_response(
                message="User not found",
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Prevent modifying super admin (except by super admin)
        if user.role == 'SUPER_ADMIN' and request.user.role != 'SUPER_ADMIN':
            return error_response(
                message="You don't have permission to modify super admin",
                status=status.HTTP_403_FORBIDDEN
            )
        
        serializer = UserStatusUpdateSerializer(data=request.data)
        
        if not serializer.is_valid():
            return error_response(
                message="Validation failed",
                errors=serializer.errors,
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Update user status
        if 'status' in serializer.validated_data:
            user.status = serializer.validated_data['status']
        
        if 'is_active' in serializer.validated_data:
            user.is_active = serializer.validated_data['is_active']
        
        user.save()
        
        # Log the action
        action_map = {
            'ACTIVE': 'USER_ACTIVATED',
            'INACTIVE': 'USER_DEACTIVATED',
            'SUSPENDED': 'USER_SUSPENDED',
        }
        
        from .models import AuditLog
        AuditLog.objects.create(
            user=user,
            action=action_map.get(user.status, 'PROFILE_UPDATED'),
            ip_address=get_client_ip(request),
            user_agent=get_user_agent(request),
            details={
                'updated_by': str(request.user.id),
                'reason': serializer.validated_data.get('reason', ''),
            }
        )
        
        user_data = UserDetailSerializer(user).data
        
        return success_response(
            data=user_data,
            message="User status updated successfully",
            status=status.HTTP_200_OK
        )


class LoginHistoryView(generics.ListAPIView):
    """
    Get login history for authenticated user.
    """
    serializer_class = LoginHistorySerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        return LoginHistory.objects.filter(user=self.request.user)
    
    @swagger_auto_schema(
        operation_description="Get login history for current user",
        responses={
            200: LoginHistorySerializer(many=True),
            401: 'Unauthorized'
        }
    )
    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)
