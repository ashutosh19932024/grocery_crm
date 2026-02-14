from rest_framework import serializers
from .models import Product

class ProductSerializer(serializers.ModelSerializer):
    class Meta:
        model = Product
        fields = [
            "product_id", "name", "brand", "category", "subcategory",
            "price", "mrp", "discount_percentage",
            "quantity", "in_stock", "rating", "number_of_ratings",
            "image_url"
        ]
