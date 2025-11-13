"""
Custom middleware for audit logging and request tracking.
"""

import logging
from .models import AuditLog
from .utils import get_client_ip, get_user_agent

logger = logging.getLogger(__name__)


class AuditLoggingMiddleware:
    """
    Middleware to log important authentication and user management events.
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        # Process request
        response = self.get_response(request)
        
        # Log specific events based on path and method
        self._log_request(request, response)
        
        return response
    
    def _log_request(self, request, response):
        """Log requests to authentication endpoints."""
        
        # Only log successful authentication-related requests
        if response.status_code not in [200, 201]:
            return
        
        user = request.user if hasattr(request, 'user') and request.user.is_authenticated else None
        path = request.path
        method = request.method
        
        # Map paths to audit actions
        audit_actions = {
            '/api/v1/auth/register/': 'USER_REGISTERED',
            '/api/v1/auth/login/': 'USER_LOGIN',
            '/api/v1/auth/login-otp/': 'USER_LOGIN',
            '/api/v1/auth/logout/': 'USER_LOGOUT',
            '/api/v1/auth/reset-password/': 'PASSWORD_RESET',
            '/api/v1/auth/profile/': 'PROFILE_UPDATED' if method == 'PUT' else None,
        }
        
        action = audit_actions.get(path)
        
        if action:
            try:
                AuditLog.objects.create(
                    user=user,
                    action=action,
                    ip_address=get_client_ip(request),
                    user_agent=get_user_agent(request),
                    details={
                        'path': path,
                        'method': method,
                    }
                )
            except Exception as e:
                logger.error(f"Error creating audit log: {str(e)}")
