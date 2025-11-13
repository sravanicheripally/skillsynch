# admin_app/urls.py
from django.urls import path
from .views import (
    ApproveInstituteView,
    ListPendingInstitutesView,
    RejectInstituteView,
    ListPendingCoursesView,
    ApproveCourseView,
    RejectCourseView,
    InstitutesSummaryView,
    ToggleInstituteStatusView,
)
from .company_view import (
    ListPendingCompanyView,
    ApproveCompanyView,
    RejectCompanyView,
    ListPendingJobsView,
    ApproveJobView,
    RejectJobView
)


urlpatterns = [
    path('institute/pending/', ListPendingInstitutesView.as_view(), name="pending-institutes"),
    path('institute/<uuid:user_id>/approve/', ApproveInstituteView.as_view(), name="approve-institute"),
    path('institute/<uuid:user_id>/reject/', RejectInstituteView.as_view(), name='reject-institute'),
    path('institutes/summary/', InstitutesSummaryView.as_view(), name='institutes-summary'),
    path("courses/pending/", ListPendingCoursesView.as_view(), name="pending-courses"),
    path("courses/<uuid:course_id>/approve/", ApproveCourseView.as_view(), name="approve-course"),
    path("courses/<uuid:course_id>/reject/", RejectCourseView.as_view(), name="reject-course"),
    path('institutes/<int:institute_id>/toggle-status/', ToggleInstituteStatusView.as_view(), name='toggle-institute-status'),
    path('company/pending/', ListPendingCompanyView.as_view(), name="pending-companies"),
    path('company/<uuid:user_id>/approve/', ApproveCompanyView.as_view(), name="approve-company"),
    path('company/<uuid:user_id>/reject/', RejectCompanyView.as_view(), name='reject-company'),
    path('company/job/pending/', ListPendingJobsView.as_view(), name="pending-jobs"),
    path('company/job/<int:job_id>/approve/', ApproveJobView.as_view(), name="approve-job"),
    path('company/job/<int:job_id>/reject/', RejectJobView.as_view(), name='reject-job'),
]
