from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import  JobPostingViewSet, CompanyDocumentViewSet

router = DefaultRouter()
router.register(r'jobs', JobPostingViewSet, basename='jobposting')
router.register(r'documents', CompanyDocumentViewSet, basename='companydocument')

urlpatterns = [
    path('', include(router.urls)),
]
