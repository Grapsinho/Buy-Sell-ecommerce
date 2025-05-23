import uuid
from django.db import models
from django.conf import settings
from django.utils import timezone

from product_management.models import Product


class Address(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    # should be foreign key
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='address'
    )
    street = models.CharField(max_length=255)
    city = models.CharField(max_length=100)
    region = models.CharField(max_length=100)
    postal_code = models.CharField(max_length=20)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.street}, {self.city}, {self.region}, {self.postal_code}"


class ShippingMethod(models.Model):
    PICKUP = 'pickup'
    CITY = 'city'
    REGIONAL = 'regional'
    TYPE_CHOICES = [
        (PICKUP, 'Pick-up'),
        (CITY, 'City Delivery'),
        (REGIONAL, 'Regional Delivery'),
    ]

    name = models.CharField(max_length=20, choices=TYPE_CHOICES, unique=True)
    flat_fee = models.DecimalField(max_digits=10, decimal_places=2)
    lead_time_min = models.DurationField()
    lead_time_max = models.DurationField()

    def __str__(self):
        return self.name


class Order(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='orders'
    )
    shipping_method = models.ForeignKey(
        ShippingMethod,
        on_delete=models.PROTECT
    )
    shipping_address = models.ForeignKey(
        Address,
        null=True,
        blank=True,
        on_delete=models.SET_NULL
    )
    shipping_fee = models.DecimalField(max_digits=10, decimal_places=2)
    total_amount = models.DecimalField(max_digits=12, decimal_places=2)
    expected_delivery_date = models.DateTimeField()

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Order {self.id} by {self.user.email}"

    @staticmethod
    def calculate_expected_delivery(method):
        return timezone.now() + method.lead_time_max


class OrderItem(models.Model):
    order = models.ForeignKey(
        Order,
        on_delete=models.CASCADE,
        related_name='items'
    )
    product = models.ForeignKey(
        Product,
        on_delete=models.PROTECT
    )
    quantity = models.PositiveIntegerField()
    unit_price = models.DecimalField(max_digits=10, decimal_places=2)
    subtotal = models.DecimalField(max_digits=12, decimal_places=2)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['order', 'product'], name='unique_order_product')
        ]

    def __str__(self):
        return f"{self.quantity}x {self.product.name}"