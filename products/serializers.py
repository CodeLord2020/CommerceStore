from rest_framework import serializers
from .models import Product, ProductAttribute, Category


class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = '__all__'

class ProductAttributeSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProductAttribute
        fields = ['id', 'name', 'value']



class ProductSerializer(serializers.ModelSerializer):
    attributes = ProductAttributeSerializer(many=True, required=False)
    
    class Meta:
        model = Product
        fields = ['id', 'owner', 'name', 'slug', 'description', 'price', 'resources', 'stock', 'available', 'created_at', 'updated_at', 'category', 'status', 'attributes']
        read_only_fields = ['owner', 'status', 'created_at', 'updated_at']

    def create(self, validated_data):
        attributes_data = validated_data.pop('attributes', [])
        product = Product.objects.create(**validated_data)
        for attribute_data in attributes_data:
            ProductAttribute.objects.create(product=product, **attribute_data)
        return product

    def update(self, instance, validated_data):
        attributes_data = validated_data.pop('attributes', [])
        instance = super().update(instance, validated_data)
        instance.attributes.all().delete()
        for attribute_data in attributes_data:
            ProductAttribute.objects.create(product=instance, **attribute_data)
        return instance