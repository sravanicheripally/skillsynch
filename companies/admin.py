from django.contrib import admin
from .models import JobPosting, CompanyDocument





@admin.register(JobPosting)
class JobPostingAdmin(admin.ModelAdmin):
    list_display = ('title', 'company', 'employment_type', 'status', 'is_active')
    search_fields = ('title', 'company__name')
    list_filter = ('employment_type', 'status')


@admin.register(CompanyDocument)
class CompanyDocumentAdmin(admin.ModelAdmin):
    list_display = ('doc_type', 'company', 'uploaded_at')
    search_fields = ('company__name', 'doc_type')
