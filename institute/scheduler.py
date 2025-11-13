from datetime import date
from apscheduler.schedulers.background import BackgroundScheduler
from .models import Batch, Enrollment

def update_batch_and_enrollment():
    today = date.today()

    batches = Batch.objects.all()
    for batch in batches:
        # Update Batch Status
        if today < batch.start_date:
            batch.status = "UPCOMING"
        elif batch.start_date <= today <= batch.end_date:
            batch.status = "ONGOING"
        else:
            batch.status = "COMPLETED"
        batch.save()

        # When batch is completed → update enrollments
        if batch.status == "COMPLETED":
            Enrollment.objects.filter(
                batch=batch,
                completion_status__in=["ENROLLED", "IN_PROGRESS"]
            ).update(completion_status="COMPLETED")

    print("✅ Batch & Enrollment status auto-updated")

def start():
    scheduler = BackgroundScheduler()
    scheduler.add_job(update_batch_and_enrollment, 'interval', days=1)  # Runs daily
    scheduler.start()
    print("Scheduler started for updating Batch & Enrollment statuses.")