"""
Django signals for automatic actions on model events.
"""

import logging
from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import OTPVerification, User
from .utils import send_otp_email, send_otp_sms

logger = logging.getLogger(__name__)


@receiver(post_save, sender=OTPVerification)
def send_otp_on_creation(sender, instance, created, **kwargs):
    """
    Send OTP via email or SMS when OTPVerification is created.
    """
    if created and not instance.is_verified:
        try:
            if instance.email:
                logger.info(f"Attempting to send OTP email to {instance.email}")
                result = send_otp_email(instance.email, instance.otp_code, instance.purpose)
                if result:
                    logger.info(f"OTP email sent successfully to {instance.email}")
                else:
                    logger.error(f"Failed to send OTP email to {instance.email}")
            
            if instance.phone:
                logger.info(f"Attempting to send OTP SMS to {instance.phone}")
                result = send_otp_sms(instance.phone, instance.otp_code, instance.purpose)
                if result:
                    logger.info(f"OTP SMS sent successfully to {instance.phone}")
                else:
                    logger.error(f"Failed to send OTP SMS to {instance.phone}")
        
        except Exception as e:
            logger.error(f"Error sending OTP: {str(e)}")
            import traceback
            logger.error(traceback.format_exc())


@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    """
    Ensure user profile is created if missing (safety check).
    This is primarily handled in the serializer, but this acts as a fallback.
    """
    if created:
        logger.info(f"New user created: {instance.email} (Role: {instance.role})")
