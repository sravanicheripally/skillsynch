"""
User models for Skillsynch platform.
Includes custom User model and role-based profile models.
"""

import uuid
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from django.core.validators import MinValueValidator, MaxValueValidator
from phonenumber_field.modelfields import PhoneNumberField


class UserManager(BaseUserManager):
    """Custom user manager for email-based authentication."""
    
    def create_user(self, email, password=None, **extra_fields):
        """Create and save a regular user."""
        if not email:
            raise ValueError('Users must have an email address')
        
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_superuser(self, email, password=None, **extra_fields):
        """Create and save a superuser."""
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('is_verified', True)
        extra_fields.setdefault('role', 'SUPER_ADMIN')
        
        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')
        
        return self.create_user(email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    """
    Custom User model with UUID primary key and role-based access.
    """
    
    ROLE_CHOICES = [
        ('STUDENT', 'Student'),
        ('INSTITUTE', 'Training Institute'),
        ('COMPANY', 'Company/Recruiter'),
        ('MENTOR', 'Mentor'),
        ('NBFC', 'NBFC Partner'),
        ('ADMIN', 'Admin'),
        ('SUPER_ADMIN', 'Super Admin'),
    ]
    
    STATUS_CHOICES = [
        ('ACTIVE', 'Active'),
        ('INACTIVE', 'Inactive'),
        ('SUSPENDED', 'Suspended'),
        ('PENDING', 'Pending Verification'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True, db_index=True)
    phone = PhoneNumberField(unique=True, db_index=True)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES)
    
    # Status fields
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    is_verified = models.BooleanField(default=False)  # Email/phone verified
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PENDING')
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_login = models.DateTimeField(null=True, blank=True)
    
    objects = UserManager()
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['phone', 'role']
    
    class Meta:
        db_table = 'users'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['email', 'role']),
            models.Index(fields=['phone', 'role']),
        ]
    
    def __str__(self):
        return f"{self.email} ({self.get_role_display()})"
    
    def get_profile(self):
        """Get the role-specific profile for this user."""
        profile_mapping = {
            'STUDENT': 'student_profile',
            'INSTITUTE': 'institute_profile',
            'COMPANY': 'company_profile',
            'MENTOR': 'mentor_profile',
            'NBFC': 'nbfc_profile',
            'ADMIN': 'admin_profile',
            'SUPER_ADMIN': 'admin_profile',
        }
        
        profile_attr = profile_mapping.get(self.role)
        return getattr(self, profile_attr, None) if profile_attr else None


class StudentProfile(models.Model):
    """Profile for Student users."""
    
    EDUCATION_LEVELS = [
        ('HIGH_SCHOOL', 'High School'),
        ('UNDERGRADUATE', 'Undergraduate'),
        ('GRADUATE', 'Graduate'),
        ('POSTGRADUATE', 'Postgraduate'),
        ('DIPLOMA', 'Diploma'),
    ]
    
    LEARNING_MODES = [
        ('ONLINE', 'Online'),
        ('OFFLINE', 'Offline'),
        ('HYBRID', 'Hybrid'),
    ]
    
    GENDER = [
        ('MALE', 'male'),
        ('FEMALE', 'female'),
    ]
    
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='student_profile')
    full_name = models.CharField(max_length=255)
    highest_qualification = models.CharField(max_length=20, choices=EDUCATION_LEVELS)
    skills = models.TextField(help_text="Comma-separated skills")
    resume = models.FileField(upload_to='resumes/', null=True, blank=True)
    city = models.CharField(max_length=100)
    date_of_birth = models.DateField(null=True, blank=True)
    bio = models.TextField(blank=True)
    gender = models.CharField(max_length=20, choices=GENDER, default='FEMALE')
    preferred_learning_mode = models.CharField(max_length=20, choices=LEARNING_MODES, default='ONLINE')
    graduation_year = models.IntegerField(null=True, blank=True)
    primary_skills_interested = models.TextField(
        help_text="Comma-separated list of primary skills of interest",
        blank=True
    )
    agreed_to_terms = models.BooleanField(default=False)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'student_profiles'
    
    def __str__(self):
        return f"{self.full_name} - Student"


class InstituteProfile(models.Model):
    """Profile for Training Institute users."""

    ADMIN_APPROVALS_STATUS = [
        ('APPROVED', 'approved'),
        ('REJECTED', 'rejected'),
        ('PENDING', 'pending'),
    ]
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='institute_profile')
   
    # Basic institute details
    institute_name = models.CharField(max_length=255)
    institute_type = models.CharField(max_length=100, blank=True, null=True)  # pvt_university etc.
    established_year = models.IntegerField(
        null=True, blank=True,
        validators=[MinValueValidator(1900), MaxValueValidator(2100)]
    )
    address = models.TextField()
    city = models.CharField(max_length=100, blank=True, null=True)
    state = models.CharField(max_length=100, blank=True, null=True)
    pincode = models.CharField(max_length=20, blank=True, null=True)
    country = models.CharField(max_length=50, blank=True, null=True)
    website = models.URLField(blank=True)
    rejection_reason = models.TextField(blank=True, null=True)
    # GST and accreditation
    pan = models.CharField(max_length=10, unique=True, null=True, blank=True)
    gst_number = models.CharField(max_length=15, unique=True)
    accreditation_certificate_no = models.CharField(max_length=50, blank=True, null=True)
    registration_certificate_no = models.CharField(max_length=50, blank=True, null=True)
   
    # Uploaded documents
    accreditation_certificate = models.FileField(upload_to='institute_docs/', null=True, blank=True)
    registration_certificate = models.FileField(upload_to='institute_docs/', null=True, blank=True)
    gst_certificate = models.FileField(upload_to='institute_docs/', null=True, blank=True)
   
    # Admin details
    admin_name = models.CharField(max_length=255, blank=True, null=True)
    admin_designation = models.CharField(max_length=100, blank=True, null=True)
    admin_phone_number = models.CharField(max_length=20, blank=True, null=True)
    admin_email = models.EmailField(blank=True, null=True)
    admin_approved = models.CharField(max_length=20, choices=ADMIN_APPROVALS_STATUS, default='PENDING')
   
    alternate_phone = models.CharField(max_length=20, blank=True, null=True)
    courses_offered = models.TextField(blank=True, null=True)
    facilities = models.TextField(blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    logo = models.ImageField(upload_to='institute_logos/', blank=True, null=True)
   
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=False)
    class Meta:
        db_table = 'institute_profiles'
   
    def __str__(self):
        return f"{self.institute_name} - Institute"
 

class CompanyProfile(models.Model):
    """Profile for Company/Recruiter users."""
    
    COMPANY_SIZES = [
        ('1-10', '1-10 employees'),
        ('11-50', '11-50 employees'),
        ('51-200', '51-200 employees'),
        ('201-500', '201-500 employees'),
        ('501-1000', '501-1000 employees'),
        ('1001+', '1001+ employees'),
    ]
    
    ADMIN_APPROVALS_STATUS = [
        ('APPROVED', 'approved'),
        ('REJECTED', 'rejected'),
        ('PENDING', 'pending'),
    ]
    
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='company_profile')
    company_name = models.CharField(max_length=255)
    cin_number = models.CharField(max_length=21, unique=True)
    industry = models.CharField(max_length=100)
    website = models.URLField(blank=True)
    company_size = models.CharField(max_length=20, choices=COMPANY_SIZES)
    address = models.TextField()
    logo = models.ImageField(upload_to='company_logos/', null=True, blank=True)
    description = models.TextField(blank=True)
    admin_approved = models.CharField(max_length=20, choices=ADMIN_APPROVALS_STATUS, default='PENDING')
    rejection_reason = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'company_profiles'
    
    def __str__(self):
        return f"{self.company_name} - Company"


class MentorProfile(models.Model):
    """Profile for Mentor users."""
    
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='mentor_profile')
    full_name = models.CharField(max_length=255)
    experience_years = models.IntegerField(validators=[MinValueValidator(0)])
    expertise_areas = models.TextField(help_text="Comma-separated expertise areas")
    linkedin_url = models.URLField(blank=True)
    bio = models.TextField()
    hourly_rate = models.DecimalField(
        max_digits=10, 
        decimal_places=2,
        validators=[MinValueValidator(0)],
        null=True,
        blank=True
    )
    profile_picture = models.ImageField(upload_to='mentor_pictures/', null=True, blank=True)
    certifications = models.TextField(blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'mentor_profiles'
    
    def __str__(self):
        return f"{self.full_name} - Mentor"


class NBFCProfile(models.Model):
    """Profile for NBFC Partner users."""
    
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='nbfc_profile')
    organization_name = models.CharField(max_length=255)
    nbfc_license_number = models.CharField(max_length=50, unique=True)
    contact_person = models.CharField(max_length=255)
    website = models.URLField(blank=True)
    address = models.TextField()
    logo = models.ImageField(upload_to='nbfc_logos/', null=True, blank=True)
    description = models.TextField(blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'nbfc_profiles'
    
    def __str__(self):
        return f"{self.organization_name} - NBFC Partner"


class AdminProfile(models.Model):
    """Profile for Admin and Super Admin users."""
    
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='admin_profile')
    username = models.CharField(max_length=150, unique=True)
    full_name = models.CharField(max_length=255)
    department = models.CharField(max_length=100, blank=True)
    employee_id = models.CharField(max_length=50, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'admin_profiles'
    
    def __str__(self):
        return f"{self.username} - {self.user.get_role_display()}"


class OTPVerification(models.Model):
    """Model to store OTP verification codes."""
    
    OTP_PURPOSES = [
        ('REGISTRATION', 'Registration'),
        ('LOGIN', 'Login'),
        ('PASSWORD_RESET', 'Password Reset'),
        ('EMAIL_VERIFICATION', 'Email Verification'),
        ('PHONE_VERIFICATION', 'Phone Verification'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='otps', null=True, blank=True)
    email = models.EmailField(null=True, blank=True)
    phone = PhoneNumberField(null=True, blank=True)
    otp_code = models.CharField(max_length=6)
    purpose = models.CharField(max_length=25, choices=OTP_PURPOSES)
    
    is_verified = models.BooleanField(default=False)
    attempts = models.IntegerField(default=0)
    
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    verified_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'otp_verifications'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['email', 'purpose']),
            models.Index(fields=['phone', 'purpose']),
        ]
    
    def __str__(self):
        return f"OTP for {self.email or self.phone} - {self.purpose}"
    
    def is_expired(self):
        """Check if OTP has expired."""
        from django.utils import timezone
        return timezone.now() > self.expires_at
    
    def increment_attempts(self):
        """Increment failed verification attempts."""
        self.attempts += 1
        self.save()


class LoginHistory(models.Model):
    """Track user login history."""
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='login_history')
    
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    device_info = models.CharField(max_length=255, blank=True)
    location = models.CharField(max_length=255, blank=True)
    
    login_method = models.CharField(
        max_length=20,
        choices=[('PASSWORD', 'Password'), ('OTP', 'OTP')],
        default='PASSWORD'
    )
    
    success = models.BooleanField(default=True)
    failure_reason = models.CharField(max_length=255, blank=True)
    
    logged_in_at = models.DateTimeField(auto_now_add=True)
    logged_out_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'login_history'
        ordering = ['-logged_in_at']
        indexes = [
            models.Index(fields=['user', 'logged_in_at']),
        ]
    
    def __str__(self):
        return f"{self.user.email} - {self.ip_address} at {self.logged_in_at}"


class AuditLog(models.Model):
    """Audit logging for authentication and important events."""
    
    ACTION_TYPES = [
        ('USER_REGISTERED', 'User Registered'),
        ('USER_LOGIN', 'User Login'),
        ('USER_LOGOUT', 'User Logout'),
        ('PASSWORD_CHANGED', 'Password Changed'),
        ('PASSWORD_RESET', 'Password Reset'),
        ('EMAIL_VERIFIED', 'Email Verified'),
        ('PHONE_VERIFIED', 'Phone Verified'),
        ('PROFILE_UPDATED', 'Profile Updated'),
        ('USER_ACTIVATED', 'User Activated'),
        ('USER_DEACTIVATED', 'User Deactivated'),
        ('USER_SUSPENDED', 'User Suspended'),
        ('OTP_GENERATED', 'OTP Generated'),
        ('OTP_VERIFIED', 'OTP Verified'),
        ('OTP_FAILED', 'OTP Verification Failed'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='audit_logs')
    action = models.CharField(max_length=30, choices=ACTION_TYPES)
    
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    
    details = models.JSONField(default=dict, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'audit_logs'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['user', 'action', 'timestamp']),
            models.Index(fields=['action', 'timestamp']),
        ]
    
    def __str__(self):
        user_email = self.user.email if self.user else 'Anonymous'
        return f"{user_email} - {self.action} at {self.timestamp}"
