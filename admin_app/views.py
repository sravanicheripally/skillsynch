# admin_app/views.py

from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status

from users.models import User, InstituteProfile,CompanyProfile
from .serializers import PendingInstituteSerializer, InstituteSummarySerializer
from users.permissions import IsAdmin
from institute.models import Course
from .serializers import PendingCourseSerializer,RejectCourseSerializer,PendingCompanySerializer
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from django.db.models import Count



class ListPendingInstitutesView(APIView):
    permission_classes = [IsAdmin]

    def get(self, request):
        pending_users = InstituteProfile.objects.filter(admin_approved='PENDING')
        serializer = PendingInstituteSerializer(pending_users, many=True)
        return Response({"pending_institutes": serializer.data}, status=status.HTTP_200_OK)


class InstitutesSummaryView(APIView):
    """Return a summarized list of institutes with course and student counts.

    Response format (list of objects):
    - id
    - name (institute_name)
    - email (user.email)
    - phone (user.phone)
    - courses (number of courses created by the institute)
    - students (number of distinct students enrolled in any batch of the institute)
    - status (Active/Pending/Rejected)
    """

    permission_classes = [IsAdmin]

    def get(self, request):
        # Annotate institutes with counts. Use distinct names to avoid conflict
        # with the reverse related_name `courses` on InstituteProfile.
        qs = InstituteProfile.objects.select_related('user').filter(
            admin_approved__in=["APPROVED", "REJECTED"]
        ).annotate(
            courses_count=Count('courses', distinct=True),
            students_count=Count('courses__batches__enrollments__student', distinct=True)
        )

        serializer = InstituteSummarySerializer(qs, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class ApproveInstituteView(APIView):
    permission_classes = [IsAdmin]

    def post(self, request, user_id):
        try:
            user = User.objects.get(id=user_id, role="INSTITUTE")
        except User.DoesNotExist:
            return Response({"error": "Institute not found"}, status=status.HTTP_404_NOT_FOUND)

        profile = InstituteProfile.objects.get(user=user)

        # Approve
        # admin_approved is a CharField with choices ('APPROVED','REJECTED','PENDING')
        profile.admin_approved = 'APPROVED'
        profile.save(update_fields=['admin_approved'])

        user.status = "ACTIVE"
        user.is_verified = True
        user.save(update_fields=['status', 'is_verified'])

        return Response({"message": "Institute approved successfully"}, status=status.HTTP_200_OK)


class RejectInstituteView(APIView):
    permission_classes = [IsAdmin]
    @swagger_auto_schema(
        request_body=RejectCourseSerializer,
        responses={200: "Course rejection response"}
    )

    def post(self, request, user_id):
        try:
            inst_profile = InstituteProfile.objects.get(user_id=user_id)
        except InstituteProfile.DoesNotExist:
            return Response({"error": "Institute not found."}, status=status.HTTP_404_NOT_FOUND)

        reason = request.data.get("reason", "").strip()

        inst_profile.admin_approved = 'REJECTED'
        inst_profile.rejection_reason = reason
        inst_profile.save(update_fields=['admin_approved', 'rejection_reason'])

        return Response({
            "message": "Institute registration rejected successfully",
            "rejected_institute": inst_profile.institute_name,
            "reason": reason
        }, status=status.HTTP_200_OK)


class ListPendingCoursesView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        pending_courses = Course.objects.filter(status="PENDING")
        serializer = PendingCourseSerializer(pending_courses, many=True)
        return Response({"pending_courses": serializer.data}, status=status.HTTP_200_OK)


class ApproveCourseView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, course_id):
        try:
            course = Course.objects.get(id=course_id, status="PENDING")
        except Course.DoesNotExist:
            return Response({"error": "Course not found or already processed."}, status=404)

        course.status = "APPROVED"
        course.save(update_fields=['status'])
        return Response({"message": "Course approved successfully"}, status=200)


class RejectCourseView(APIView):
    permission_classes = [AllowAny]
    @swagger_auto_schema(
        request_body=RejectCourseSerializer,
        responses={200: "Course rejection response"}
    )

    def post(self, request, course_id):
        
        serializer = RejectCourseSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        reason = serializer.validated_data['reason']

        try:
            course = Course.objects.get(id=course_id, status="PENDING")
        except Course.DoesNotExist:
            return Response({"error": "Course not found or already processed."}, status=404)

        course.status = "REJECTED"
        course.rejection_reason = reason
        course.save(update_fields=['status', 'rejection_reason'])

        return Response({
            "message": "Course rejected successfully",
            "course": course.name,
            "reason": reason
        }, status=200)


class ToggleInstituteStatusView(APIView):
    permission_classes = [IsAdmin]

    def post(self, request, institute_id):
        try:
            institute = InstituteProfile.objects.get(id=institute_id)
        except InstituteProfile.DoesNotExist:
            return Response(
                {"error": "Institute not found"},
                status=status.HTTP_404_NOT_FOUND
            )

        # Toggle logic
        if institute.admin_approved == "APPROVED":
            institute.admin_approved = "REJECTED"
            action = "blocked"
        elif institute.admin_approved == "REJECTED":
            institute.admin_approved = "APPROVED"
            action = "unblocked"
        else:
            return Response(
                {"error": "Institute must be either APPROVED or REJECTED to toggle"},
                status=status.HTTP_400_BAD_REQUEST
            )

        institute.save()
        return Response(
            {"message": f"Institute {action} successfully"},
            status=status.HTTP_200_OK
        )