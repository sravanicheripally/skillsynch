from rest_framework import serializers
from .models import  JobPosting, CompanyDocument




class JobPostingSerializer(serializers.ModelSerializer):
    class Meta:
        model = JobPosting
        fields = '__all__'
        read_only_fields = ('id', 'created_at', 'updated_at')


# serializers.py
class CompanyDocumentSerializer(serializers.ModelSerializer):
    class Meta:
        model = CompanyDocument
        fields = "__all__"
        read_only_fields = ("id", "uploaded_at", "company", "uploaded_by")
