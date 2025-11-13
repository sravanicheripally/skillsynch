from django.urls import path
from payments.views import CreatePaymentOrderView, VerifyPaymentView

urlpatterns = [
    path('create-payment/', CreatePaymentOrderView.as_view(), name='create_payment'),
    path('verify-payment/', VerifyPaymentView.as_view(), name='verify_payment'),
]
