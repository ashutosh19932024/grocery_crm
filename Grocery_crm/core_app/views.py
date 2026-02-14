from rest_framework import generics
from .models import Product
from .serializers import ProductSerializer
from rest_framework.views import APIView
from rest_framework.response import Response
from collections import defaultdict

class ProductCreateView(generics.CreateAPIView):
    queryset = Product.objects.all()
    serializer_class = ProductSerializer

class ProductListView(generics.ListAPIView):
    """List view for products. Supports optional `search` query param.

    `category` is a plain CharField in the model (not a relation),
    so don't use select_related here.
    """
    serializer_class = ProductSerializer

    def get_queryset(self):
        search = self.request.query_params.get("search")

        queryset = Product.objects.all()

        if search:
            queryset = queryset.filter(name__icontains=search)

        return queryset

class ProductCategoryGroupedView(APIView):

    def get(self, request):
        search = request.query_params.get("search")

        queryset = Product.objects.all()

        if search:
            queryset = queryset.filter(name__icontains=search)

        serializer = ProductSerializer(queryset, many=True)

        grouped_data = defaultdict(list)

        for product in serializer.data:
            category_name = product.get("category") or "Others"
            grouped_data[category_name].append(product)

        # Convert defaultdict to normal dict
        return Response(dict(grouped_data))