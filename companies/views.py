from rest_framework import viewsets, permissions
from .models import  JobPosting, CompanyDocument
from .serializers import JobPostingSerializer, CompanyDocumentSerializer
from rest_framework.permissions import AllowAny
from users.permissions import IsCompany

class IsCompanyOwnerOrReadOnly(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.method in permissions.SAFE_METHODS:
            return True
        return getattr(obj, 'owner', None) == request.user



class JobPostingViewSet(viewsets.ModelViewSet):
    queryset = JobPosting.objects.all()
    serializer_class = JobPostingSerializer
    permission_classes = [AllowAny]

    def perform_create(self, serializer):
        # ensure posted_by is set to the requesting user if not provided
        serializer.save(posted_by=self.request.user)


# views.py
class CompanyDocumentViewSet(viewsets.ModelViewSet):
    queryset = CompanyDocument.objects.all()
    serializer_class = CompanyDocumentSerializer
    permission_classes = [AllowAny]  # ensure only company users can upload

    def get_queryset(self):
        # A company can only view its own documents
        return self.queryset.filter(company=self.request.user.company_profile)

    def perform_create(self, serializer):
        company = self.request.user.company_profile
        serializer.save(company=company, uploaded_by=self.request.user)
