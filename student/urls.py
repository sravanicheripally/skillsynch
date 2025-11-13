from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    StudentCourseListView,
    StudentBatchListView,
    StudentEnrollmentViewSet,
    StudentCourseWithBatchesView,
    StudentJobListView
)

router = DefaultRouter()
# router.register(r'profile', StudentProfileViewSet, basename='student-profile')
router.register(r'enrollments', StudentEnrollmentViewSet, basename='student-enrollment')

urlpatterns = [
    path('', include(router.urls)),
    path('student_courses/', StudentCourseListView.as_view(), name='student-courses'),
    path('student_batches/', StudentBatchListView.as_view(), name='student-batches'),
    path('courses-with-batches/', StudentCourseWithBatchesView.as_view(), name='student-courses-with-batches'),
    path('jobs/', StudentJobListView.as_view(), name='student-jobs'),
]
