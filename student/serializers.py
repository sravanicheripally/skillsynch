from rest_framework import serializers
from users.models import StudentProfile
from institute.models import Course, Batch, Enrollment
from .exceptions import InvalidObjectException
from rest_framework.exceptions import ValidationError
from companies.models import JobPosting

# ---------- STUDENT PROFILE ----------
class StudentProfileSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(source='user.email', read_only=True)

    class Meta:
        model = StudentProfile
        fields = [
            'id', 'email', 'full_name', 'highest_qualification',
            'skills', 'city', 'graduation_year'
        ]


# ---------- COURSE LIST (for students) ----------
class StudentCourseSerializer(serializers.ModelSerializer):
    institute_name = serializers.CharField(source='institute.institute_name', read_only=True)

    class Meta:
        model = Course
        fields = ['id', 'name', 'description', 'mode', 'duration_weeks', 'fee', 'status', 'institute_name']


# ---------- BATCH LIST ----------
class StudentBatchSerializer(serializers.ModelSerializer):
    course_name = serializers.CharField(source='course.name', read_only=True)

    class Meta:
        model = Batch
        fields = ['id', 'course_name', 'name', 'start_date', 'end_date', 'capacity', 'status']


# ---------- ENROLLMENT ----------
class StudentEnrollmentSerializer(serializers.ModelSerializer):
    batch_name = serializers.CharField(source='batch.name', read_only=True)
    course_name = serializers.CharField(source='batch.course.name', read_only=True)

    class Meta:
        model = Enrollment
        fields = [
            'id', 'batch', 'batch_name', 'course_name',
            'payment_status', 'completion_status',
            'enrollment_date', 'certificate_issued'
        ]
    def run_validation(self, data):
        try:
            return super().run_validation(data)
        except ValidationError as e:
            # Detect the "does_not_exist" case
            if "does_not_exist" in str(e):
                raise InvalidObjectException("Batch does not exist.")
            raise e


# ---------- COURSE WITH BATCHES ----------
class StudentCourseWithBatchesSerializer(serializers.ModelSerializer):
    batches = serializers.SerializerMethodField()
    institute_name = serializers.CharField(source='institute.institute_name', read_only=True)

    class Meta:
        model = Course
        fields = ['id', 'name', 'description', 'mode', 'duration_weeks', 'fee', 'institute_name', 'batches']

    def get_batches(self, obj):
        batches = Batch.objects.filter(course=obj, status__in=['UPCOMING', 'ONGOING'])
        return StudentBatchSerializer(batches, many=True).data


class JobPostingSerializer(serializers.ModelSerializer):
    company_name = serializers.CharField(source='company.name', read_only=True)

    class Meta:
        model = JobPosting
        fields = ['id', 'title', 'description', 'location', 'salary_range', 'experience_required', 'skills_required', 'company_name']
