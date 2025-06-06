from django.apps import AppConfig


class ProductManagementConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'product_management'

    def ready(self):
        import product_management.signals
