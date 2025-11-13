# admin_app/serializers.py

from rest_framework import serializers
from users.models import User, InstituteProfile, CompanyProfile
from institute.models import Course


class PendingInstituteSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(source="user.email")
    phone = serializers.CharField(source="user.phone")

    class Meta:
        model = InstituteProfile
        fields = [
            "institute_name", "gst_number", "city", "state",
            "admin_approved", "email", "phone", "user_id"
        ]

class PendingCourseSerializer(serializers.ModelSerializer):
    institute_name = serializers.CharField(source="institute.institute_name", read_only=True)

    class Meta:
        model = Course
        fields = ["id", "name", "description", "duration_weeks", "mode", "fee", "status", "institute_name"]
        
class RejectCourseSerializer(serializers.Serializer):
    reason = serializers.CharField(required=True)


class InstituteSummarySerializer(serializers.ModelSerializer):
    id = serializers.IntegerField(source='pk')
    name = serializers.CharField(source='institute_name')
    email = serializers.EmailField(source='user.email')
    phone = serializers.CharField(source='user.phone')
    courses = serializers.IntegerField(source='courses_count')
    students = serializers.IntegerField(source='students_count')
    status = serializers.SerializerMethodField()

    class Meta:
        model = InstituteProfile
        fields = [
            'id', 'name', 'email', 'phone', 'courses', 'students', 'status'
        ]

    def get_status(self, obj):
        # Only two statuses now: Approved OR Rejected
        return "Approved" if obj.admin_approved == "APPROVED" else "Rejected"


class PendingCompanySerializer(serializers.ModelSerializer):
    email = serializers.EmailField(source="user.email")
    phone = serializers.CharField(source="user.phone")

    class Meta:
        model = CompanyProfile
        fields = "__all__"
        
class RejectJobSerializer(serializers.Serializer):
    reason = serializers.CharField(required=True)