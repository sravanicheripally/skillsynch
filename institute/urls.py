# institute/urls.py
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import CourseViewSet, BatchViewSet, EnrollmentViewSet,IssueCertificatesAPIView


router = DefaultRouter()
router.register(r'courses', CourseViewSet, basename='course')
router.register(r'batches', BatchViewSet, basename='batch')
router.register(r'enrollments', EnrollmentViewSet, basename='enrollment')

urlpatterns = [
    path('', include(router.urls)),
    path('issue/<uuid:batch_id>/', IssueCertificatesAPIView.as_view()),

    
]
