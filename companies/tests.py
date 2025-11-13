from django.test import TestCase
from .models import Company


class CompanyModelTest(TestCase):
    def test_company_creation(self):
        c = Company.objects.create(name='Acme Test')
        self.assertEqual(str(c), 'Acme Test')
