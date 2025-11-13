from rest_framework import serializers
from .models import Course, Batch, Enrollment,Certificate
from .validations import DateRangeValidator
from.exceptions import InvalidObjectReferenceException
from .utils import generate_certificate_id

# ---------- COURSE SERIALIZER ----------
class CourseSerializer(serializers.ModelSerializer):
    class Meta:
        model = Course
        fields = '__all__'
        read_only_fields = ['id', 'status', 'institute']
        
    def validate_duration_weeks(self, value):
        if value <= 0:
            raise serializers.ValidationError("Duration must be greater than 0 weeks.")
        return value
    
    def run_validation(self, data):
        """
        Catch DRF's 'Invalid pk ... does not exist' errors before reaching the view.
        """
        try:
            return super().run_validation(data)
        except serializers.ValidationError as e:
            if "does_not_exist" in str(e):
                raise InvalidObjectReferenceException(
                    "The selected course does not exist or has been removed."
                )
            raise e

# ---------- BATCH SERIALIZER ----------
class BatchSerializer(serializers.ModelSerializer):
    course_name = serializers.CharField(source='course.name', read_only=True)
    fee = serializers.DecimalField(source='course.fee', max_digits=10, decimal_places=2, read_only=True)
    class Meta:
        model = Batch
        fields = '__all__'
        read_only_fields = ['id', 'status']
        validators = [DateRangeValidator()] 
    def validate_capacity(self, value):
        """Ensure capacity > 0."""
        if value <= 0:
            raise serializers.ValidationError("Capacity must be greater than 0.")
        return value

    def run_validation(self, data):
        """
        Catch DRF's 'Invalid pk ... does not exist' errors before reaching the view.
        """
        try:
            return super().run_validation(data)
        except serializers.ValidationError as e:
            if "does_not_exist" in str(e):
                raise InvalidObjectReferenceException(
                    "The selected course does not exist or has been removed."
                )
            raise e

# ---------- ENROLLMENT SERIALIZER ----------
class EnrollmentSerializer(serializers.ModelSerializer):
    # Corrected related field mappings
    name = serializers.CharField(source='student.full_name', read_only=True)
    email = serializers.EmailField(source='student.user.email', read_only=True)
    phone = serializers.CharField(source='student.user.phone', read_only=True)
    resume = serializers.FileField(source='student.resume', read_only=True)
    course_name = serializers.CharField(source='batch.course.name', read_only=True)
    batch_name = serializers.CharField(source='batch.name', read_only=True)

    class Meta:
        model = Enrollment
        fields = [
            'id',
            'name',
            'course_name',
            'batch_name',
            'email',
            'phone',
            'resume',
            'payment_status',
            'enrollment_date',
            'completion_status',
            'certificate_issued',
            'student',
            'batch',
        ]
        read_only_fields = ['id', 'enrollment_date']

    def validate(self, data):
        if Enrollment.objects.filter(
            student=data['student'], batch=data['batch']
        ).exists():
            raise serializers.ValidationError("Student is already enrolled in this batch.")
        return data

    def run_validation(self, data):
        try:
            return super().run_validation(data)
        except serializers.ValidationError as e:
            if "does_not_exist" in str(e):
                raise InvalidObjectReferenceException(
                    "The selected course or batch does not exist or has been removed."
                )
            raise e



class CertificateSerializer(serializers.ModelSerializer):
    student_name = serializers.CharField(source='student.user.full_name', read_only=True)
    course_name = serializers.CharField(source='course.name', read_only=True)

    class Meta:
        model = Certificate
        fields = ['student_name', 'course_name', 'certificate_id', 'issue_date']
    
    def create(self, validated_data):
        student = validated_data['student']
        course = validated_data['course']
        institute = course.institute

        certificate_id = generate_certificate_id(institute.name)
        validated_data['certificate_id'] = certificate_id

        return super().create(validated_data)