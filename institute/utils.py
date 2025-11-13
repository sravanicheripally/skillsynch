# certificates/utils.py
from datetime import datetime
from .models import Certificate

def generate_certificate_id(institute_name):
    prefix = institute_name[:3].upper()
    year = datetime.now().year
    count = Certificate.objects.filter(issue_date__year=year).count() + 1
    return f"{prefix}-{year}-{str(count).zfill(3)}"
