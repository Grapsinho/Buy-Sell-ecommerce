from django.apps import AppConfig


class ProductCartConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'product_cart'

    def ready(self):
        import product_cart.signals