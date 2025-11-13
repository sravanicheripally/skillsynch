"""
Utility functions for OTP, email, SMS, and other helpers.
"""

import random
import logging
from datetime import timedelta
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from rest_framework.views import exception_handler
from rest_framework.response import Response
from .models import OTPVerification, AuditLog

logger = logging.getLogger(__name__)


# OTP Utilities
def generate_otp():
    """Generate a 6-digit OTP."""
    return str(random.randint(100000, 999999))


def create_otp(identifier, purpose, user=None):
    """
    Create and store OTP for verification.
    
    Args:
        identifier: Email or phone number
        purpose: Purpose of OTP (from OTP_PURPOSES)
        user: User instance (optional)
    
    Returns:
        OTPVerification instance
    """
    otp_code = generate_otp()
    expires_at = timezone.now() + timedelta(seconds=settings.OTP_EXPIRY_TIME)
    
    # Determine if identifier is email or phone
    is_email = '@' in identifier
    
    otp = OTPVerification.objects.create(
        user=user,
        email=identifier if is_email else None,
        phone=identifier if not is_email else None,
        otp_code=otp_code,
        purpose=purpose,
        expires_at=expires_at
    )
    
    logger.info(f"OTP generated for {identifier}: {otp_code} (Purpose: {purpose})")
    
    # Log audit event
    AuditLog.objects.create(
        user=user,
        action='OTP_GENERATED',
        details={
            'identifier': identifier,
            'purpose': purpose,
        }
    )
    
    return otp


def verify_otp(identifier, otp_code, purpose):
    """
    Verify OTP code.
    
    Args:
        identifier: Email or phone number
        otp_code: OTP code to verify
        purpose: Purpose of OTP
    
    Returns:
        tuple: (success: bool, message: str, otp: OTPVerification or None)
    """
    is_email = '@' in identifier
    
    try:
        if is_email:
            otp = OTPVerification.objects.filter(
                email=identifier,
                purpose=purpose,
                is_verified=False
            ).order_by('-created_at').first()
        else:
            otp = OTPVerification.objects.filter(
                phone=identifier,
                purpose=purpose,
                is_verified=False
            ).order_by('-created_at').first()
        
        if not otp:
            return False, "No OTP found for this identifier.", None
        
        # Check if OTP has expired
        if otp.is_expired():
            return False, "OTP has expired.", None
        
        # Check if max attempts exceeded
        if otp.attempts >= settings.OTP_MAX_ATTEMPTS:
            return False, "Maximum verification attempts exceeded.", None
        
        # Verify OTP code
        if otp.otp_code != otp_code:
            otp.increment_attempts()
            
            # Log failed attempt
            AuditLog.objects.create(
                user=otp.user,
                action='OTP_FAILED',
                details={
                    'identifier': identifier,
                    'purpose': purpose,
                    'attempts': otp.attempts,
                }
            )
            
            return False, "Invalid OTP code.", None
        
        # Mark OTP as verified
        otp.is_verified = True
        otp.verified_at = timezone.now()
        otp.save()
        
        # Log successful verification
        AuditLog.objects.create(
            user=otp.user,
            action='OTP_VERIFIED',
            details={
                'identifier': identifier,
                'purpose': purpose,
            }
        )
        
        return True, "OTP verified successfully.", otp
    
    except Exception as e:
        logger.error(f"Error verifying OTP: {str(e)}")
        return False, "An error occurred during verification.", None


def can_resend_otp(identifier, purpose):
    """
    Check if OTP can be resent (cooldown check).
    
    Args:
        identifier: Email or phone number
        purpose: Purpose of OTP
    
    Returns:
        tuple: (can_resend: bool, message: str, wait_seconds: int)
    """
    is_email = '@' in identifier
    cooldown_time = timezone.now() - timedelta(seconds=settings.OTP_RESEND_COOLDOWN)
    
    if is_email:
        last_otp = OTPVerification.objects.filter(
            email=identifier,
            purpose=purpose
        ).order_by('-created_at').first()
    else:
        last_otp = OTPVerification.objects.filter(
            phone=identifier,
            purpose=purpose
        ).order_by('-created_at').first()
    
    if last_otp and last_otp.created_at > cooldown_time:
        wait_seconds = int((last_otp.created_at + timedelta(seconds=settings.OTP_RESEND_COOLDOWN) - timezone.now()).total_seconds())
        return False, f"Please wait {wait_seconds} seconds before requesting a new OTP.", wait_seconds
    
    return True, "OTP can be resent.", 0


# Email Utilities
def send_otp_email(email, otp_code, purpose):
    """
    Send OTP via email.
    
    Args:
        email: Recipient email address
        otp_code: OTP code to send
        purpose: Purpose of OTP
    """
    purpose_map = {
        'REGISTRATION': 'Registration',
        'LOGIN': 'Login',
        'PASSWORD_RESET': 'Password Reset',
        'EMAIL_VERIFICATION': 'Email Verification',
        'PHONE_VERIFICATION': 'Phone Verification',
    }
    
    subject = f"Your Skillsynch {purpose_map.get(purpose, 'Verification')} OTP"
    message = f"""
    Hello,
    
    Your OTP for {purpose_map.get(purpose, 'verification')} is: {otp_code}
    
    This OTP is valid for {settings.OTP_EXPIRY_TIME // 60} minutes.
    
    If you didn't request this OTP, please ignore this email.
    
    Best regards,
    Skillsynch Team
    """
    
    try:
        logger.info(f"Sending OTP email to {email} with subject: {subject}")
        logger.info(f"Email backend: {settings.EMAIL_BACKEND}")
        logger.info(f"Email host: {settings.EMAIL_HOST}")
        logger.info(f"From email: {settings.DEFAULT_FROM_EMAIL}")
        
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email],
            fail_silently=False,
        )
        logger.info(f"OTP email sent successfully to {email}")
        return True
    except Exception as e:
        logger.error(f"Failed to send OTP email to {email}: {str(e)}")
        import traceback
        logger.error(traceback.format_exc())
        return False


# SMS Utilities (Console/Twilio/AWS SNS)
def send_otp_sms(phone, otp_code, purpose):
    """
    Send OTP via SMS.
    Supports console output (dev) and Twilio/AWS SNS (production).
    
    Args:
        phone: Recipient phone number
        otp_code: OTP code to send
        purpose: Purpose of OTP
    """
    purpose_map = {
        'REGISTRATION': 'Registration',
        'LOGIN': 'Login',
        'PASSWORD_RESET': 'Password Reset',
        'EMAIL_VERIFICATION': 'Email Verification',
        'PHONE_VERIFICATION': 'Phone Verification',
    }
    
    message = f"Your Skillsynch {purpose_map.get(purpose, 'Verification')} OTP is: {otp_code}. Valid for {settings.OTP_EXPIRY_TIME // 60} minutes."
    
    # Console output for development
    if settings.DEBUG or not (settings.TWILIO_ACCOUNT_SID or settings.AWS_ACCESS_KEY_ID):
        logger.info(f"SMS to {phone}: {message}")
        print(f"\n{'='*60}\nSMS to {phone}:\n{message}\n{'='*60}\n")
        return True
    
    # Twilio integration
    if settings.TWILIO_ACCOUNT_SID:
        return send_sms_twilio(phone, message)
    
    # AWS SNS integration
    if settings.AWS_ACCESS_KEY_ID:
        return send_sms_aws(phone, message)
    
    logger.warning("No SMS service configured")
    return False


def send_sms_twilio(phone, message):
    """Send SMS via Twilio."""
    try:
        from twilio.rest import Client
        
        client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
        message = client.messages.create(
            body=message,
            from_=settings.TWILIO_PHONE_NUMBER,
            to=str(phone)
        )
        
        logger.info(f"SMS sent via Twilio to {phone}, SID: {message.sid}")
        return True
    except Exception as e:
        logger.error(f"Failed to send SMS via Twilio: {str(e)}")
        return False


def send_sms_aws(phone, message):
    """Send SMS via AWS SNS."""
    try:
        import boto3
        
        sns_client = boto3.client(
            'sns',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_REGION
        )
        
        response = sns_client.publish(
            PhoneNumber=str(phone),
            Message=message
        )
        
        logger.info(f"SMS sent via AWS SNS to {phone}, MessageID: {response['MessageId']}")
        return True
    except Exception as e:
        logger.error(f"Failed to send SMS via AWS SNS: {str(e)}")
        return False


# Request Helpers
def get_client_ip(request):
    """Extract client IP address from request."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def get_user_agent(request):
    """Extract user agent from request."""
    return request.META.get('HTTP_USER_AGENT', '')


def get_device_info(request):
    """Extract device information from user agent."""
    user_agent = get_user_agent(request)
    
    # Simple device detection
    if 'Mobile' in user_agent:
        return 'Mobile'
    elif 'Tablet' in user_agent:
        return 'Tablet'
    else:
        return 'Desktop'


# Exception Handler
def custom_exception_handler(exc, context):
    """Custom exception handler for DRF."""
    response = exception_handler(exc, context)
    
    if response is not None:
        # Customize error response format
        custom_response = {
            'success': False,
            'error': {
                'message': response.data if isinstance(response.data, str) else str(response.data),
                'status_code': response.status_code,
            }
        }
        
        # Add detail if available
        if isinstance(response.data, dict):
            if 'detail' in response.data:
                custom_response['error']['message'] = response.data['detail']
            else:
                custom_response['error']['details'] = response.data
        
        response.data = custom_response
    
    return response


# Response Helpers
def success_response(data=None, message="Success", status=200):
    """Standard success response format."""
    return Response({
        'success': True,
        'message': message,
        'data': data
    }, status=status)


def error_response(message="Error", errors=None, status=400):
    """Standard error response format."""
    response_data = {
        'success': False,
        'message': message
    }
    
    if errors:
        response_data['errors'] = errors
    
    return Response(response_data, status=status)
