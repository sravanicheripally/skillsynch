"""
Serializers for user management and authentication.
"""

from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from .models import (
    User, StudentProfile, InstituteProfile, CompanyProfile,
    MentorProfile, NBFCProfile, AdminProfile, OTPVerification, LoginHistory
)
import re

# Profile Serializers
class StudentProfileSerializer(serializers.ModelSerializer):
    """Serializer for Student profile."""
    
    class Meta:
        model = StudentProfile
        fields = [
            'full_name', 'highest_qualification', 'skills', 'resume',
            'city', 'date_of_birth', 'bio','preferred_learning_mode',
            'gender','graduation_year','primary_skills_interested','agreed_to_terms'
        ]
        extra_kwargs = {
            'resume': {'required': False},
            'date_of_birth': {'required': False},
            'bio': {'required': False},
        }


class InstituteProfileSerializer(serializers.ModelSerializer):
    """Serializer for Institute profile."""
    email = serializers.EmailField(source='user.email', read_only=True)
    phone = serializers.CharField(source='user.phone', read_only=True)

    class Meta:
        model = InstituteProfile
        fields = ['institute_name','institute_type','established_year','email','phone', 
                  'address','city','state','pincode','country','website','gst_number', 'pan','accreditation_certificate_no',
            'registration_certificate_no',
            'accreditation_certificate',
            'registration_certificate',
            'gst_certificate',
            'admin_name',
            'admin_designation',
            'admin_phone_number',
            'admin_email',
            'admin_approved',
             'alternate_phone',
             'courses_offered',
             'facilities',
            'description', 'logo',           
            'created_at', 'updated_at',
            'created_at',
            'updated_at',
        ]

        extra_kwargs = {
            'website': {'required': False},
            'institute_type': {'required': False},
            'established_year': {'required': False},
            'city': {'required': False},
            'state': {'required': False},
            'pincode': {'required': False},
            'country': {'required': False},
            'accreditation_certificate_no': {'required': False},
            'registration_certificate_no': {'required': False},
            'accreditation_certificate': {'required': False},
            'registration_certificate': {'required': False},
            'gst_certificate': {'required': False},
            'admin_name': {'required': False},
            'admin_designation': {'required': False},
            'admin_phone_number': {'required': False},
            'admin_email': {'required': False},
            'admin_approved': {'required': False},
            'pan':{'required':True}
        }
    def validate_pan_number(self, value):
        if value and not re.match(r'^[A-Z]{5}[0-9]{4}[A-Z]$', value.upper()):
            raise serializers.ValidationError("Invalid PAN format. Example: ABCDE1234F")
        return value.upper()


class CompanyProfileSerializer(serializers.ModelSerializer):
    """Serializer for Company profile."""
    
    class Meta:
        model = CompanyProfile
        fields = [
            'company_name', 'cin_number', 'industry', 'website',
            'company_size', 'address', 'logo', 'description'
        ]
        extra_kwargs = {
            'website': {'required': False},
            'logo': {'required': False},
            'description': {'required': False},
        }


class MentorProfileSerializer(serializers.ModelSerializer):
    """Serializer for Mentor profile."""
    
    class Meta:
        model = MentorProfile
        fields = [
            'full_name', 'experience_years', 'expertise_areas',
            'linkedin_url', 'bio', 'hourly_rate', 'profile_picture', 'certifications'
        ]
        extra_kwargs = {
            'linkedin_url': {'required': False},
            'hourly_rate': {'required': False},
            'profile_picture': {'required': False},
            'certifications': {'required': False},
        }


class NBFCProfileSerializer(serializers.ModelSerializer):
    """Serializer for NBFC Partner profile."""
    
    class Meta:
        model = NBFCProfile
        fields = [
            'organization_name', 'nbfc_license_number', 'contact_person',
            'website', 'address', 'logo', 'description'
        ]
        extra_kwargs = {
            'website': {'required': False},
            'logo': {'required': False},
            'description': {'required': False},
        }


class AdminProfileSerializer(serializers.ModelSerializer):
    """Serializer for Admin/SuperAdmin profile."""
    
    class Meta:
        model = AdminProfile
        fields = ['username', 'full_name', 'department', 'employee_id']
        extra_kwargs = {
            'department': {'required': False},
            'employee_id': {'required': False},
        }


# User Registration Serializer
class UserRegistrationSerializer(serializers.ModelSerializer):
    """Serializer for user registration."""
    
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    password_confirm = serializers.CharField(write_only=True, required=True)
    
    # Profile data (dynamic based on role)
    profile_data = serializers.JSONField(write_only=True, required=True)
    
    class Meta:
        model = User
        fields = ['email', 'phone', 'role', 'password', 'password_confirm', 'profile_data']
    
    def validate(self, attrs):
        """Validate password match and profile data."""
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError({"password": "Passwords do not match."})
        
        # Validate profile data based on role
        role = attrs.get('role')
        profile_data = attrs.get('profile_data', {})
        
        profile_serializers = {
            'STUDENT': StudentProfileSerializer,
            'INSTITUTE': InstituteProfileSerializer,
            'COMPANY': CompanyProfileSerializer,
            'MENTOR': MentorProfileSerializer,
            'NBFC': NBFCProfileSerializer,
            'ADMIN': AdminProfileSerializer,
            'SUPER_ADMIN': AdminProfileSerializer,
        }
        
        serializer_class = profile_serializers.get(role)
        if serializer_class:
            profile_serializer = serializer_class(data=profile_data)
            if not profile_serializer.is_valid():
                raise serializers.ValidationError({
                    "profile_data": profile_serializer.errors
                })
        
        return attrs
    
    def create(self, validated_data):
        """Create user and associated profile."""
        validated_data.pop('password_confirm')
        profile_data = validated_data.pop('profile_data')
        password = validated_data.pop('password')
        
             # Create user
        user = User.objects.create_user(password=password, **validated_data)
         #  If institute → mark pending approval
        if user.role == 'INSTITUTE':
            user.status = 'PENDING'            # pending admin review
            user.is_verified = False           # cannot login until approved
            user.save()

            InstituteProfile.objects.create(
                user=user,
                institute_name=profile_data.get('institute_name'),
                gst_number=profile_data.get('gst_number'),
                address=profile_data.get('address'),
                city=profile_data.get('city'),
                state=profile_data.get('state'),
                pincode=profile_data.get('pincode'),
                country=profile_data.get('country'),
                website=profile_data.get('website'),
                admin_approved=profile_data.get('admin_approved', 'PENDING')           # default pending
            )
            return user

        # Create role-specific profile
        self._create_profile(user, profile_data)
        
        return user
    
    def _create_profile(self, user, profile_data):
        """Create role-specific profile."""
        profile_models = {
            'STUDENT': StudentProfile,
            'INSTITUTE': InstituteProfile,
            'COMPANY': CompanyProfile,
            'MENTOR': MentorProfile,
            'NBFC': NBFCProfile,
            'ADMIN': AdminProfile,
            'SUPER_ADMIN': AdminProfile,
        }
        
        profile_model = profile_models.get(user.role)
        if profile_model:
            profile_model.objects.create(user=user, **profile_data)


# OTP Serializers
class OTPVerificationSerializer(serializers.Serializer):
    """Serializer for OTP verification."""
    
    identifier = serializers.CharField(help_text="Email or phone number")
    otp_code = serializers.CharField(max_length=6, min_length=6)
    purpose = serializers.ChoiceField(choices=OTPVerification.OTP_PURPOSES)
    
    def validate_otp_code(self, value):
        """Validate OTP code format."""
        if not value.isdigit():
            raise serializers.ValidationError("OTP must contain only digits.")
        return value


class OTPRequestSerializer(serializers.Serializer):
    """Serializer for OTP generation request."""
    
    identifier = serializers.CharField(help_text="Email or phone number")
    purpose = serializers.ChoiceField(choices=OTPVerification.OTP_PURPOSES)


# Login Serializers
class LoginSerializer(serializers.Serializer):
    """Serializer for email/phone + password login."""
    
    identifier = serializers.CharField(help_text="Email or phone number")
    password = serializers.CharField(write_only=True)
    
    def validate(self, attrs):
        """Validate login credentials."""
        identifier = attrs.get('identifier')
        password = attrs.get('password')
        
        # Try to find user by email or phone
        user = None
        if '@' in identifier:
            try:
                user = User.objects.get(email=identifier)
            except User.DoesNotExist:
                raise serializers.ValidationError("Invalid credentials.")
        else:
            try:
                user = User.objects.get(phone=identifier)
            except User.DoesNotExist:
                raise serializers.ValidationError("Invalid credentials.")
        
        if not user.check_password(password):
            raise serializers.ValidationError("Invalid credentials.")
        
        if not user.is_active:
            raise serializers.ValidationError("User account is disabled.")
        
        attrs['user'] = user
        return attrs


class OTPLoginSerializer(serializers.Serializer):
    """Serializer for OTP-based login."""
    
    identifier = serializers.CharField(help_text="Email or phone number")
    otp_code = serializers.CharField(max_length=6, min_length=6)


class PasswordResetRequestSerializer(serializers.Serializer):
    """Serializer for password reset request."""
    
    identifier = serializers.CharField(help_text="Email or phone number")


class PasswordResetConfirmSerializer(serializers.Serializer):
    """Serializer for password reset confirmation."""
    
    identifier = serializers.CharField(help_text="Email or phone number")
    otp = serializers.CharField(max_length=6, min_length=6)
    new_password = serializers.CharField(write_only=True, validators=[validate_password])
    new_password_confirm = serializers.CharField(write_only=True)
    
    def validate(self, attrs):
        """Validate password match."""
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError({"new_password": "Passwords do not match."})
        return attrs

# User Profile Serializers
class UserDetailSerializer(serializers.ModelSerializer):
    """Serializer for user details with profile."""
    
    profile = serializers.SerializerMethodField()
    role_display = serializers.CharField(source='get_role_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    
    class Meta:
        model = User
        fields = [
            'id', 'email', 'phone', 'role', 'role_display',
            'status', 'status_display', 'is_active', 'is_verified',
            'created_at', 'updated_at', 'last_login', 'profile'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at', 'last_login']
    
    def get_profile(self, obj):
        """Get role-specific profile data."""
        profile = obj.get_profile()
        if not profile:
            return None
        
        serializers_map = {
            'STUDENT': StudentProfileSerializer,
            'INSTITUTE': InstituteProfileSerializer,
            'COMPANY': CompanyProfileSerializer,
            'MENTOR': MentorProfileSerializer,
            'NBFC': NBFCProfileSerializer,
            'ADMIN': AdminProfileSerializer,
            'SUPER_ADMIN': AdminProfileSerializer,
        }
        
        serializer_class = serializers_map.get(obj.role)
        if serializer_class:
            return serializer_class(profile).data
        return None


class ProfileUpdateSerializer(serializers.Serializer):
    """Serializer for profile updates."""
    
    profile_data = serializers.JSONField(required=True)
    
    def validate(self, attrs):
        """Validate profile data based on user role."""
        user = self.context['request'].user
        profile_data = attrs.get('profile_data', {})
        
        serializers_map = {
            'STUDENT': StudentProfileSerializer,
            'INSTITUTE': InstituteProfileSerializer,
            'COMPANY': CompanyProfileSerializer,
            'MENTOR': MentorProfileSerializer,
            'NBFC': NBFCProfileSerializer,
            'ADMIN': AdminProfileSerializer,
            'SUPER_ADMIN': AdminProfileSerializer,
        }
        
        serializer_class = serializers_map.get(user.role)
        if serializer_class:
            profile = user.get_profile()
            profile_serializer = serializer_class(profile, data=profile_data, partial=True)
            if not profile_serializer.is_valid():
                raise serializers.ValidationError({
                    "profile_data": profile_serializer.errors
                })
            attrs['profile_serializer'] = profile_serializer
        
        return attrs
    
    def save(self):
        """Update profile."""
        profile_serializer = self.validated_data.get('profile_serializer')
        if profile_serializer:
            profile_serializer.save()
        return self.context['request'].user


# Admin Serializers
class UserListSerializer(serializers.ModelSerializer):
    """Serializer for user list (admin view)."""
    
    role_display = serializers.CharField(source='get_role_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    
    class Meta:
        model = User
        fields = [
            'id', 'email', 'phone', 'role', 'role_display',
            'status', 'status_display', 'is_active', 'is_verified',
            'created_at', 'last_login'
        ]


class UserStatusUpdateSerializer(serializers.Serializer):
    """Serializer for updating user status (admin only)."""
    
    status = serializers.ChoiceField(choices=User.STATUS_CHOICES)
    is_active = serializers.BooleanField(required=False)
    reason = serializers.CharField(required=False, allow_blank=True)


# Login History Serializer
class LoginHistorySerializer(serializers.ModelSerializer):
    """Serializer for login history."""
    
    class Meta:
        model = LoginHistory
        fields = [
            'id', 'ip_address', 'user_agent', 'device_info',
            'location', 'login_method', 'success', 'failure_reason',
            'logged_in_at', 'logged_out_at'
        ]
        read_only_fields = fields
