# Generated by Django 5.1.7 on 2025-04-19 09:52

from decimal import Decimal
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('product_cart', '0003_alter_cartitem_unit_price'),
    ]

    operations = [
        migrations.AddField(
            model_name='cart',
            name='total_price',
            field=models.DecimalField(decimal_places=2, default=Decimal('0.00'), help_text='Cached sum of all items (quantity * unit price)', max_digits=12),
        ),
    ]
