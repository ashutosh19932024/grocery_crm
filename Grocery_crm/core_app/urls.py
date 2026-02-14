from django.urls import path
from .views import ProductCreateView, ProductListView, ProductCategoryGroupedView

urlpatterns = [
    path("create/", ProductCreateView.as_view(), name="product-create"),
    path("list/", ProductListView.as_view(), name="product-list"),
    path("list/category/", ProductCategoryGroupedView.as_view(), name="product-list-category"),
]