from rest_framework import viewsets, generics, permissions, status
from rest_framework.response import Response
from django.core.exceptions import ObjectDoesNotExist
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny

from users.models import StudentProfile
from institute.models import Course, Batch, Enrollment
from .serializers import (
    StudentProfileSerializer,
    StudentCourseSerializer,
    StudentBatchSerializer,
    StudentEnrollmentSerializer,
    StudentCourseWithBatchesSerializer,
    JobPostingSerializer
)
from users.permissions import IsStudent
from student.exceptions import (
    NotAStudentException,
    CourseNotAvailableException,
    BatchNotAvailableException,
    DuplicateEnrollmentException,
    UnexpectedErrorException
)   
from companies.models import JobPosting
# ==============================================================
# Student Course List View
# ==============================================================

class StudentCourseListView(generics.ListAPIView):
    serializer_class = StudentCourseSerializer
    permission_classes = [IsStudent]

    def get_queryset(self):
        try:
            user = self.request.user
            if not hasattr(user, 'student_profile'):
                raise NotAStudentException()

            student = user.student_profile

            # Get all enrolled course IDs
            enrolled_course_ids = Enrollment.objects.filter(
                student=student
            ).values_list('batch__course_id', flat=True)

            # Exclude already enrolled courses
            return Course.objects.filter(
                status='APPROVED'
            ).exclude(id__in=enrolled_course_ids)

        except Exception as e:
            raise UnexpectedErrorException(detail=str(e))



# ==============================================================
# Student Batch List View
# ==============================================================

class StudentBatchListView(generics.ListAPIView):
    serializer_class = StudentBatchSerializer
    permission_classes = [IsStudent]

    def get_queryset(self):
        try:
            if not hasattr(self.request.user, 'student_profile'):
                raise NotAStudentException()

            # Only upcoming or ongoing batches are visible
            return Batch.objects.filter(status__in=['UPCOMING', 'ONGOING'])

        except Exception as e:
            raise UnexpectedErrorException(detail=str(e))


# ==============================================================
# Student Enrollment ViewSet
# ==============================================================

class StudentEnrollmentViewSet(viewsets.ModelViewSet):
    serializer_class = StudentEnrollmentSerializer
    permission_classes = [IsStudent]

    def get_queryset(self):
        try:
            if not hasattr(self.request.user, 'student_profile'):
                raise NotAStudentException()
            return Enrollment.objects.filter(student__user=self.request.user)
        except Exception as e:
            raise UnexpectedErrorException(detail=str(e))

    def perform_create(self, serializer):
        try:
            # Ensure the user has a valid student profile
            student_profile = self.request.user.student_profile

            # Validate batch
            batch = serializer.validated_data.get('batch')
            if not batch or batch.status not in ['UPCOMING', 'ONGOING']:
                raise BatchNotAvailableException()

            # Prevent duplicate enrollment
            if Enrollment.objects.filter(student=student_profile, batch=batch).exists():
                raise DuplicateEnrollmentException()

            # Save enrollment
            serializer.save(student=student_profile)

        except ObjectDoesNotExist:
            raise NotAStudentException()
        except (BatchNotAvailableException, DuplicateEnrollmentException) as e:
            raise e
        except Exception as e:
            raise UnexpectedErrorException(detail=str(e))

class StudentCourseWithBatchesView(generics.ListAPIView):
    serializer_class = StudentCourseWithBatchesSerializer
    permission_classes = [IsStudent]

    def get_queryset(self):
        try:
            if not hasattr(self.request.user, 'student_profile'):
                raise NotAStudentException()

            # Only approved courses are visible to students
            return Course.objects.filter(status='APPROVED')

        except Exception as e:
            raise UnexpectedErrorException(detail=str(e))


class StudentJobListView(APIView):
    permission_classes = [IsStudent]  # or AllowAny if public

    def get(self, request):
        jobs = JobPosting.objects.filter(status="OPEN",is_active=True).select_related('company')
        print("Approved jobs count:", jobs.count())
        print( jobs,'00000000000000000000')
        serializer = JobPostingSerializer(jobs, many=True)
        return Response({"jobs": serializer.data})
