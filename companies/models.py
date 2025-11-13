import uuid
from django.db import models
from django.conf import settings
from django.utils import timezone
from users.models import CompanyProfile, User


class JobPosting(models.Model):
    """Job posting created by a Company."""

    EMPLOYMENT_TYPE = [
        ('FULL_TIME', 'Full time'),
        ('PART_TIME', 'Part time'),
        ('INTERNSHIP', 'Internship'),
        ('CONTRACT', 'Contract'),
        ('TEMPORARY', 'Temporary'),
    ]

    STATUS = [
        ('DRAFT', 'Draft'),
        ('PENDING', 'Pending'),
        ('APPROVED', 'Approved'),
        ('REJECTED', 'Rejected'),
        ('OPEN', 'Open'),
        ('CLOSED', 'Closed'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    company = models.ForeignKey(CompanyProfile, on_delete=models.CASCADE, related_name='jobs')
    title = models.CharField(max_length=255)
    description = models.TextField()
    location = models.CharField(max_length=255, blank=True)
    employment_type = models.CharField(max_length=20, choices=EMPLOYMENT_TYPE, default='FULL_TIME')

    min_experience_years = models.IntegerField(null=True, blank=True)
    max_experience_years = models.IntegerField(null=True, blank=True)
    qualification = models.CharField(max_length=255, blank=True)
    skills = models.TextField(blank=True, help_text='Comma separated skills')

    salary_min = models.IntegerField(null=True, blank=True)
    salary_max = models.IntegerField(null=True, blank=True)

    posted_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='posted_jobs'
    )

    status = models.CharField(max_length=20, choices=STATUS, default='PENDING')
    is_active = models.BooleanField(default=True)
    rejection_reason = models.TextField(blank=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    application_deadline = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'company_job_postings'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['company', 'title']),
            models.Index(fields=['status']),
        ]

    def is_open(self):
        if self.status != 'OPEN' or not self.is_active:
            return False
        if self.application_deadline and timezone.now() > self.application_deadline:
            return False
        return True

    def __str__(self):
        return f"{self.title} @ {self.company.company_name}"


class CompanyDocument(models.Model):
    DOC_TYPES = [
        ('PAN', 'PAN'),
        ('GST', 'GST'),
        ('INCORPORATION', 'Incorporation Certificate'),
        ('OTHER', 'Other'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    company = models.ForeignKey(CompanyProfile, on_delete=models.CASCADE, related_name='documents')
    doc_type = models.CharField(max_length=50, choices=DOC_TYPES, default='OTHER')
    document = models.FileField(upload_to='company_docs/')
    note = models.TextField(blank=True)
    uploaded_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'company_documents'
        indexes = [models.Index(fields=['company', 'doc_type'])]

    def __str__(self):
        return f"{self.doc_type} - {self.company.company_name}"
