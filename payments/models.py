# payments/models.py
import uuid
from django.db import models
from django.utils import timezone
from users.models import StudentProfile
from institute.models import Course, Batch, Enrollment

class PaymentTransaction(models.Model):
    PAYMENT_STATUS = [
        ('CREATED', 'Created'),
        ('SUCCESS', 'Success'),
        ('FAILED', 'Failed'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    student = models.ForeignKey(StudentProfile, on_delete=models.CASCADE, related_name='transactions')
    enrollment = models.OneToOneField(Enrollment, on_delete=models.CASCADE, related_name='transaction', null=True, blank=True)

    razorpay_order_id = models.CharField(max_length=100, unique=True)
    razorpay_payment_id = models.CharField(max_length=100, blank=True, null=True)
    razorpay_signature = models.CharField(max_length=255, blank=True, null=True)
    
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    currency = models.CharField(max_length=10, default="INR")
    status = models.CharField(max_length=10, choices=PAYMENT_STATUS, default='CREATED')
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    paid_at = models.DateTimeField(null=True, blank=True)

    def mark_success(self, payment_id, signature):
        self.status = 'SUCCESS'
        self.razorpay_payment_id = payment_id
        self.razorpay_signature = signature
        self.paid_at = timezone.now()
        self.save()
