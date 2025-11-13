"""
URL Configuration for skillsynch_backend project.
"""

from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi

# Swagger/OpenAPI Schema Configuration
schema_view = get_schema_view(
    openapi.Info(
        title="Skillsynch API",
        default_version='v1',
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
)

urlpatterns = [
    path('admin/', admin.site.urls),
    
    # API v1 endpoints
    path('api/v1/auth/', include('users.urls')),
    path('api/v1/institute/', include('institute.urls')),
    path('api/v1/student/',include('student.urls')),
    path('api/v1/admin/', include('admin_app.urls')),
    path('api/v1/companies/', include('companies.urls')),
    path('api/v1/payments/', include('payments.urls')),
    
    # API Documentation
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
    path('swagger.json', schema_view.without_ui(cache_timeout=0), name='schema-json'),
]

# Serve media files in development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
