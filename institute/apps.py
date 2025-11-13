from django.apps import AppConfig


class InstituteConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'institute'
    
    def ready(self):
        from .scheduler import start
        start()
