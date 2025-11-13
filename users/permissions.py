"""
Custom permissions for role-based access control.
"""

from rest_framework import permissions


class IsAdmin(permissions.BasePermission):
    """Permission for Admin and Super Admin only."""
    
    def has_permission(self, request, view):
        return (
            request.user and 
            request.user.is_authenticated and 
            request.user.role in ['ADMIN', 'SUPER_ADMIN']
        )


class IsSuperAdmin(permissions.BasePermission):
    """Permission for Super Admin only."""
    
    def has_permission(self, request, view):
        return (
            request.user and 
            request.user.is_authenticated and 
            request.user.role == 'SUPER_ADMIN'
        )


class IsStudent(permissions.BasePermission):
    """Permission for Students only."""
    
    def has_permission(self, request, view):
        return (
            request.user and 
            request.user.is_authenticated and 
            request.user.role == 'STUDENT'
        )


class IsInstitute(permissions.BasePermission):
    """Permission for Training Institutes only."""
    
    def has_permission(self, request, view):
        return (
            request.user and 
            request.user.is_authenticated and 
            request.user.role == 'INSTITUTE'
        )


class IsCompany(permissions.BasePermission):
    """Permission for Companies only."""
    
    def has_permission(self, request, view):
        return (
            request.user and 
            request.user.is_authenticated and 
            request.user.role == 'COMPANY'
        )


class IsMentor(permissions.BasePermission):
    """Permission for Mentors only."""
    
    def has_permission(self, request, view):
        return (
            request.user and 
            request.user.is_authenticated and 
            request.user.role == 'MENTOR'
        )


class IsNBFC(permissions.BasePermission):
    """Permission for NBFC Partners only."""
    
    def has_permission(self, request, view):
        return (
            request.user and 
            request.user.is_authenticated and 
            request.user.role == 'NBFC'
        )


class IsOwnerOrAdmin(permissions.BasePermission):
    """Permission for resource owner or admin."""
    
    def has_object_permission(self, request, view, obj):
        # Allow admins
        if request.user.role in ['ADMIN', 'SUPER_ADMIN']:
            return True
        
        # Check if user is the owner
        if hasattr(obj, 'user'):
            return obj.user == request.user
        
        return obj == request.user


class IsVerified(permissions.BasePermission):
    """Permission for verified users only."""
    
    def has_permission(self, request, view):
        return (
            request.user and 
            request.user.is_authenticated and 
            request.user.is_verified
        )


class IsActive(permissions.BasePermission):
    """Permission for active users only."""
    
    def has_permission(self, request, view):
        return (
            request.user and 
            request.user.is_authenticated and 
            request.user.is_active and
            request.user.status == 'ACTIVE'
        )
