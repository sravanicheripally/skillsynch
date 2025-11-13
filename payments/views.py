# payments/views.py
import razorpay
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from users.permissions import IsStudent
from institute.models import Batch, Enrollment
from payments.models import PaymentTransaction
from payments.serializers import (
    CreatePaymentOrderSerializer,
    VerifyPaymentSerializer,
    PaymentTransactionSerializer
)
from drf_yasg.utils import swagger_auto_schema

client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))


class CreatePaymentOrderView(APIView):
    permission_classes = [IsStudent]
    @swagger_auto_schema(
        request_body=CreatePaymentOrderSerializer,
        responses={200: "Payment order creation response"}
    )
    def post(self, request):
        serializer = CreatePaymentOrderSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        batch_id = serializer.validated_data["batch_id"]
        student = request.user.student_profile
        batch = Batch.objects.get(id=batch_id)
        course = batch.course

        # Create enrollment with payment pending
        enrollment = Enrollment.objects.create(
            student=student,
            batch=batch,
            payment_status='PENDING',
            completion_status='ENROLLED'
        )

        amount = int(course.fee * 100)  # Razorpay needs amount in paise
        order = client.order.create({
            "amount": amount,
            "currency": "INR",
            "payment_capture": 1
        })

        transaction = PaymentTransaction.objects.create(
            student=student,
            enrollment=enrollment,
            razorpay_order_id=order["id"],
            amount=course.fee,
            status="CREATED"
        )

        return Response({
            "key": settings.RAZORPAY_KEY_ID,
            "order_id": order["id"],
            "amount": amount,
            "currency": "INR",
            "student_name": student.full_name,
            "student_email": student.user.email,
            "transaction_id": str(transaction.id),
        }, status=status.HTTP_200_OK)


class VerifyPaymentView(APIView):
    permission_classes = [IsStudent]

    def post(self, request):
        serializer = VerifyPaymentSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        try:
            transaction = PaymentTransaction.objects.get(
                razorpay_order_id=data["razorpay_order_id"]
            )

            params_dict = {
                'razorpay_order_id': data["razorpay_order_id"],
                'razorpay_payment_id': data["razorpay_payment_id"],
                'razorpay_signature': data["razorpay_signature"]
            }

            # Signature verification
            client.utility.verify_payment_signature(params_dict)

            # Mark success
            transaction.mark_success(
                payment_id=data["razorpay_payment_id"],
                signature=data["razorpay_signature"]
            )

            # Update enrollment
            enrollment = transaction.enrollment
            enrollment.payment_status = "PAID"
            enrollment.save(update_fields=["payment_status"])

            return Response({"message": "Payment verified successfully"}, status=status.HTTP_200_OK)

        except razorpay.errors.SignatureVerificationError:
            transaction.status = "FAILED"
            transaction.save(update_fields=["status"])
            return Response({"error": "Payment verification failed"}, status=status.HTTP_400_BAD_REQUEST)
        except PaymentTransaction.DoesNotExist:
            return Response({"error": "Transaction not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class TransactionHistoryView(APIView):
    permission_classes = [IsStudent]

    def get(self, request):
        student = request.user.student_profile
        transactions = PaymentTransaction.objects.filter(student=student).order_by('-created_at')
        serializer = PaymentTransactionSerializer(transactions, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
