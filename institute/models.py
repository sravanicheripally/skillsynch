import uuid
from django.db import models
from django.utils import timezone
from users.models import User
from users.models import InstituteProfile
from users.models import StudentProfile


# =====================================================
#  COURSE MODEL
# =====================================================
class Course(models.Model):
    MODES = [
        ('ONLINE', 'Online'),
        ('OFFLINE', 'Offline'),
        ('HYBRID', 'Hybrid'),
    ]

    STATUSES = [
        ('PENDING', 'Pending'),
        ('APPROVED', 'Approved'),
        ('ACTIVE', 'Active'),
        ('REJECTED', 'Rejected'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    institute = models.ForeignKey(
        InstituteProfile, on_delete=models.CASCADE, related_name='courses'
    )
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    duration_weeks = models.PositiveIntegerField()
    mode = models.CharField(max_length=10, choices=MODES)
    fee = models.DecimalField(max_digits=10, decimal_places=2)
    status = models.CharField(max_length=10, choices=STATUSES, default='PENDING')
    rejection_reason = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('institute', 'name')
        ordering = ['name']

    def __str__(self):
        return f"{self.name} ({self.get_mode_display()})"


# =====================================================
#  BATCH MODEL
# =====================================================
class Batch(models.Model):
    STATUSES = [
        ('UPCOMING', 'Upcoming'),
        ('ONGOING', 'Ongoing'),
        ('COMPLETED', 'Completed'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    course = models.ForeignKey(
        Course, on_delete=models.CASCADE, related_name='batches'
    )
    name = models.CharField(max_length=255)
    start_date = models.DateField()
    end_date = models.DateField()
    capacity = models.PositiveIntegerField()
    schedule = models.JSONField(blank=True, null=True)  # Example: {"Mon": "10-12", "Wed": "2-4"}
    status = models.CharField(max_length=10, choices=STATUSES, default='UPCOMING')
    slot = models.CharField(max_length=200, blank=True, null=True)  # Deprecated field
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('course', 'name')
        constraints = [
            models.CheckConstraint(check=models.Q(end_date__gte=models.F('start_date')), name='end_date_after_start_date'),
            models.CheckConstraint(check=models.Q(capacity__gt=0), name='capacity_positive'),
        ]
        ordering = ['start_date']

    def __str__(self):
        return f"{self.name} - {self.course.name}"

# =====================================================
#  ENROLLMENT MODEL
# =====================================================

class Enrollment(models.Model):
    PAYMENT_STATUSES = [
        ('PENDING', 'Pending'),
        ('PAID', 'Paid'),
        ('FAILED', 'Failed'),
    ]

    COMPLETION_STATUSES = [
        ('ENROLLED', 'Enrolled'),
        ('IN_PROGRESS', 'In Progress'),
        ('COMPLETED', 'Completed'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    student = models.ForeignKey(
        StudentProfile, on_delete=models.CASCADE, related_name='enrollments'
    )
    batch = models.ForeignKey(
        Batch, on_delete=models.CASCADE, related_name='enrollments'
    )

    payment_status = models.CharField(max_length=10, choices=PAYMENT_STATUSES, default='PENDING')
    enrollment_date = models.DateTimeField(default=timezone.now)
    completion_status = models.CharField(max_length=12, choices=COMPLETION_STATUSES, default='ENROLLED')
    certificate_issued = models.BooleanField(default=False)

    class Meta:
        unique_together = ('student', 'batch')
        ordering = ['-enrollment_date']

    def __str__(self):
        return f"{self.student.full_name} → {self.batch.name}"


class Certificate(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    certificate_id = models.CharField(max_length=50, unique=True)
    
    student = models.ForeignKey(StudentProfile, on_delete=models.CASCADE, related_name="certificates")
    course = models.ForeignKey(Course, on_delete=models.CASCADE)
    batch = models.ForeignKey(Batch, on_delete=models.CASCADE)

    issue_date = models.DateField(auto_now_add=True)

    def __str__(self):
        return self.certificate_id