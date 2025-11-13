from rest_framework import viewsets, permissions, filters
from .models import Course, Batch, Enrollment,Certificate
from .serializers import CourseSerializer, BatchSerializer, EnrollmentSerializer,CertificateSerializer
from rest_framework.permissions import AllowAny
from users.models import InstituteProfile
from users.permissions import IsInstitute
import uuid
from django.utils import timezone
from rest_framework.views import APIView
from rest_framework.response import Response
from .utils import generate_certificate_id
from rest_framework import serializers   

from .exceptions import (
    NotAnInstituteException,
    DuplicateCourseNameException,
    UnexpectedInstituteError,
    InvalidCourseOwnershipException
)
from django.db import IntegrityError

class CourseViewSet(viewsets.ModelViewSet):
    serializer_class = CourseSerializer
    permission_classes = [IsInstitute]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['name', 'mode', 'status']
    ordering_fields = ['created_at', 'fee', 'duration_weeks']

    def get_queryset(self):
        user = self.request.user
        if not user.is_authenticated or not hasattr(user, 'institute_profile'):
            return Course.objects.none()
        return Course.objects.filter(institute=user.institute_profile)

    def perform_create(self, serializer):
        try:
            user = self.request.user
            if not hasattr(user, 'institute_profile'):
                raise NotAnInstituteException()

            serializer.save(institute=user.institute_profile)

        except IntegrityError:
            # Duplicate course name for the same institute
            raise DuplicateCourseNameException()
        except NotAnInstituteException:
            raise
        except Exception as e:
            raise UnexpectedInstituteError(detail=str(e))
        


# ---------- BATCH VIEWSET ----------
class BatchViewSet(viewsets.ModelViewSet):
    serializer_class = BatchSerializer
    permission_classes = [IsInstitute]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['name', 'status']
    ordering_fields = ['start_date', 'end_date']

    def get_queryset(self):
        user = self.request.user
        if not user.is_authenticated or not hasattr(user, 'institute_profile'):
            return Batch.objects.none()
        return Batch.objects.filter(course__institute=user.institute_profile)

    def perform_create(self, serializer):
        try:
            user = self.request.user
            if not hasattr(user, 'institute_profile'):
                raise NotAnInstituteException()

            course = serializer.validated_data.get('course')

            # ✅ Prevent creating batches for unapproved courses
            if course.status != "APPROVED":
                raise serializers.ValidationError("You can create batches only for approved courses.")

            # ✅ Ensure institute owns the course
            if course.institute != user.institute_profile:
                raise InvalidCourseOwnershipException()

            serializer.save()

        except (NotAnInstituteException, InvalidCourseOwnershipException) as e:
            raise e
        except Exception as e:
            raise UnexpectedInstituteError(detail=str(e))


# ---------- ENROLLMENT VIEWSET ----------

class EnrollmentViewSet(viewsets.ModelViewSet):
    queryset = Enrollment.objects.all()
    serializer_class = EnrollmentSerializer
    permission_classes = [AllowAny]
    filter_backends = [filters.SearchFilter, filters.OrderingFilter]
    search_fields = ['student_id', 'batch_id', 'payment_status', 'completion_status']
    ordering_fields = ['enrollment_date']

    def perform_create(self, serializer):
        try:
            serializer.save()
        except Exception as e:
            raise UnexpectedInstituteError(detail=str(e))



class IssueCertificatesAPIView(APIView):
    permission_classes = [IsInstitute]

    def post(self, request, batch_id):
        try:
            # Ensure batch belongs to logged-in institute
            batch = Batch.objects.get(
                id=batch_id,
                course__institute=request.user.institute_profile
            )
            # Get students who completed and haven't received certificate yet
            enrollments = Enrollment.objects.filter(
                completion_status="COMPLETED",
                # certificate_issued=False,
                batch_id=batch.id
            )
            issued_list = []

            for enrollment in enrollments:
                student = enrollment.student
                course = batch.course

                certificate_id = generate_certificate_id(batch.course.institute.institute_name)
              
                certificate = Certificate.objects.create(
                    student=student,
                    course=course,
                    batch=batch,
                    certificate_id=certificate_id
                )

                # Mark certificate issued
                enrollment.certificate_issued = True
                enrollment.save()

                issued_list.append(CertificateSerializer(certificate).data)

            return Response({
                "success": True,
                "data": issued_list
            })

        except Batch.DoesNotExist:
            return Response({
                "success": False,
                "message": "Batch not found or it does not belong to your institute."
            }, status=404)