from django.shortcuts import render

# Create your views here.
from rest_framework import viewsets, status as rest_status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from django.shortcuts import get_object_or_404
from .models import *
from .serializers import *
from .permissions import IsOwnerOrReadOnly, IsAdminOrReadOnly


class CategoryViewSet(viewsets.ModelViewSet):
    queryset = Category.objects.all()
    serializer_class = CategorySerializer
    permission_classes = [IsAdminOrReadOnly] 


class ProductViewSet(viewsets.ModelViewSet):
    queryset = Product.objects.all()
    serializer_class = ProductSerializer
    permission_classes = [IsAuthenticated, IsOwnerOrReadOnly]

    def perform_create(self, serializer):
        serializer.save(owner=self.request.user, status='pending')

    def perform_update(self, serializer):
        if self.request.user == serializer.instance.owner:
            serializer.save(status='pending')
        else:
            serializer.save()

    @action(detail=True, methods=['patch'], permission_classes=[IsAdminUser])
    def change_status(self, request, pk=None):
        product = self.get_object()
        status = request.data.get('status')
        if status not in ['approved', 'rejected']:
            return Response({'status': 'Invalid status'}, status=rest_status.HTTP_400_BAD_REQUEST)
        product.status = status
        product.save()
        return Response({'message': 'Product status updated'}, status=rest_status.HTTP_200_OK)

    def get_queryset(self):
        queryset = Product.objects.all()
        if self.action == 'list':
            return queryset.filter(status='approved')
        return queryset