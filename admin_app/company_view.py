from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
from users.models import User, CompanyProfile
from users.permissions import IsAdmin
from .serializers import PendingCompanySerializer, RejectJobSerializer
from companies.models import JobPosting
from companies.serializers import JobPostingSerializer


class ListPendingCompanyView(APIView):
    permission_classes = [IsAdmin]

    def get(self, request):
        pending_users = CompanyProfile.objects.filter(admin_approved='PENDING')
        serializer = PendingCompanySerializer(pending_users, many=True)
        return Response({"pending_companies": serializer.data}, status=status.HTTP_200_OK)


class ApproveCompanyView(APIView):
    permission_classes = [IsAdmin]

    def post(self, request, user_id):
        try:
            user = User.objects.get(id=user_id, role="COMPANY")
        except User.DoesNotExist:
            return Response({"error": "Company not found"}, status=status.HTTP_404_NOT_FOUND)

        profile = CompanyProfile.objects.get(user=user)
        profile.admin_approved = 'APPROVED'
        profile.save(update_fields=['admin_approved'])

        user.status = "ACTIVE"
        user.is_verified = True
        user.save(update_fields=['status', 'is_verified'])

        return Response({"message": "Company approved successfully"}, status=status.HTTP_200_OK)


class RejectCompanyView(APIView):
    permission_classes = [IsAdmin]

    def post(self, request, user_id):
        try:
            inst_profile = CompanyProfile.objects.get(user_id=user_id)
        except CompanyProfile.DoesNotExist:
            return Response({"error": "Company not found."}, status=status.HTTP_404_NOT_FOUND)

        reason = request.data.get("reason", "").strip()
        inst_profile.admin_approved = 'REJECTED'
        inst_profile.rejection_reason = reason
        inst_profile.save(update_fields=['admin_approved', 'rejection_reason'])

        return Response({
            "message": "Company registration rejected successfully",
            "rejected_company": inst_profile.company_name,
            "reason": reason
        }, status=status.HTTP_200_OK)


class ListPendingJobsView(APIView):
    permission_classes = [IsAdmin]

    def get(self, request):
        jobs = JobPosting.objects.filter(status="PENDING", is_active=True).select_related('company')
        serializer = JobPostingSerializer(jobs, many=True)
        return Response({"pending_jobs": serializer.data}, status=status.HTTP_200_OK)


class ApproveJobView(APIView):
    permission_classes = [IsAdmin]

    def post(self, request, job_id):
        try:
            job = JobPosting.objects.get(id=job_id, status="PENDING")
        except JobPosting.DoesNotExist:
            return Response({"error": "Job not found or already processed."}, status=status.HTTP_404_NOT_FOUND)

        job.status = "APPROVED"
        job.rejection_reason = None
        job.save(update_fields=["status", "rejection_reason"])

        return Response({"message": "Job approved successfully"}, status=status.HTTP_200_OK)


class RejectJobView(APIView):
    permission_classes = [IsAdmin]

    def post(self, request, job_id):
        serializer = RejectJobSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        reason = serializer.validated_data['reason']

        try:
            job = JobPosting.objects.get(id=job_id, status="PENDING")
        except JobPosting.DoesNotExist:
            return Response({"error": "Job not found or already processed."}, status=status.HTTP_404_NOT_FOUND)

        job.status = "REJECTED"
        job.rejection_reason = reason
        job.save(update_fields=["status", "rejection_reason"])

        return Response({
            "message": "Job rejected successfully",
            "reason": reason
        }, status=status.HTTP_200_OK)
