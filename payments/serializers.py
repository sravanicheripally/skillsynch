# payments/serializers.py
from rest_framework import serializers
from payments.models import PaymentTransaction
from institute.models import Batch

class CreatePaymentOrderSerializer(serializers.Serializer):
    batch_id = serializers.UUIDField()

    def validate_batch_id(self, value):
        try:
            batch = Batch.objects.get(id=value)
        except Batch.DoesNotExist:
            raise serializers.ValidationError("Batch not found")
        if batch.status not in ['UPCOMING', 'ONGOING']:
            raise serializers.ValidationError("Batch not available for enrollment")
        return value


class VerifyPaymentSerializer(serializers.Serializer):
    razorpay_order_id = serializers.CharField()
    razorpay_payment_id = serializers.CharField()
    razorpay_signature = serializers.CharField()


class PaymentTransactionSerializer(serializers.ModelSerializer):
    course_name = serializers.SerializerMethodField()
    batch_name = serializers.SerializerMethodField()

    class Meta:
        model = PaymentTransaction
        fields = [
            'id',
            'razorpay_order_id',
            'razorpay_payment_id',
            'amount',
            'currency',
            'status',
            'paid_at',
            'course_name',
            'batch_name',
        ]

    def get_course_name(self, obj):
        try:
            return obj.enrollment.batch.course.name
        except Exception:
            return None

    def get_batch_name(self, obj):
        try:
            return obj.enrollment.batch.name
        except Exception:
            return None
