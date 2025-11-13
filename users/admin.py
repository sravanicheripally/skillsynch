"""
Admin configuration for user models.
"""

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import (
    User, StudentProfile, InstituteProfile, CompanyProfile,
    MentorProfile, NBFCProfile, AdminProfile,
    OTPVerification, LoginHistory, AuditLog
)


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    """Admin for User model."""
    
    list_display = ['email', 'phone', 'role', 'status', 'is_active', 'is_verified', 'created_at']
    list_filter = ['role', 'status', 'is_active', 'is_verified', 'created_at']
    search_fields = ['email', 'phone']
    ordering = ['-created_at']
    
    fieldsets = (
        (None, {'fields': ('email', 'phone', 'password')}),
        ('Role & Status', {'fields': ('role', 'status', 'is_verified')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('Important dates', {'fields': ('last_login', 'created_at', 'updated_at')}),
    )
    
    readonly_fields = ['created_at', 'updated_at', 'last_login']
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'phone', 'role', 'password1', 'password2'),
        }),
    )


@admin.register(StudentProfile)
class StudentProfileAdmin(admin.ModelAdmin):
    """Admin for StudentProfile."""
    
    list_display = ['full_name', 'user', 'highest_qualification', 'city', 'created_at']
    list_filter = ['highest_qualification', 'city']
    search_fields = ['full_name', 'user__email', 'skills']


@admin.register(InstituteProfile)
class InstituteProfileAdmin(admin.ModelAdmin):
    """Admin for InstituteProfile."""
    
    list_display = ['institute_name', 'user', 'gst_number', 'created_at']
    search_fields = ['institute_name', 'user__email', 'gst_number']


@admin.register(CompanyProfile)
class CompanyProfileAdmin(admin.ModelAdmin):
    """Admin for CompanyProfile."""
    
    list_display = ['company_name', 'user', 'cin_number', 'industry', 'company_size', 'created_at']
    list_filter = ['industry', 'company_size']
    search_fields = ['company_name', 'user__email', 'cin_number']


@admin.register(MentorProfile)
class MentorProfileAdmin(admin.ModelAdmin):
    """Admin for MentorProfile."""
    
    list_display = ['full_name', 'user', 'experience_years', 'hourly_rate', 'created_at']
    list_filter = ['experience_years']
    search_fields = ['full_name', 'user__email', 'expertise_areas']


@admin.register(NBFCProfile)
class NBFCProfileAdmin(admin.ModelAdmin):
    """Admin for NBFCProfile."""
    
    list_display = ['organization_name', 'user', 'nbfc_license_number', 'contact_person', 'created_at']
    search_fields = ['organization_name', 'user__email', 'nbfc_license_number']


@admin.register(AdminProfile)
class AdminProfileAdmin(admin.ModelAdmin):
    """Admin for AdminProfile."""
    
    list_display = ['username', 'full_name', 'user', 'department', 'created_at']
    search_fields = ['username', 'full_name', 'user__email']


@admin.register(OTPVerification)
class OTPVerificationAdmin(admin.ModelAdmin):
    """Admin for OTPVerification."""
    
    list_display = ['email', 'phone', 'purpose', 'is_verified', 'attempts', 'created_at', 'expires_at']
    list_filter = ['purpose', 'is_verified', 'created_at']
    search_fields = ['email', 'phone', 'user__email']
    readonly_fields = ['created_at', 'verified_at']


@admin.register(LoginHistory)
class LoginHistoryAdmin(admin.ModelAdmin):
    """Admin for LoginHistory."""
    
    list_display = ['user', 'ip_address', 'login_method', 'success', 'logged_in_at', 'logged_out_at']
    list_filter = ['login_method', 'success', 'logged_in_at']
    search_fields = ['user__email', 'ip_address']
    readonly_fields = ['logged_in_at', 'logged_out_at']


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    """Admin for AuditLog."""
    
    list_display = ['user', 'action', 'ip_address', 'timestamp']
    list_filter = ['action', 'timestamp']
    search_fields = ['user__email', 'action', 'ip_address']
    readonly_fields = ['timestamp']
