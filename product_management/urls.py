from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import ProductViewSet, CategoryRetrieveAPIView, ParentCategoryListAPIView, CreateProductMedia, ProductListAPIViewRame, LoadProductsFixtures

router = DefaultRouter()
router.register(r'items', ProductViewSet, basename='items')

urlpatterns = [
    path('shop/', include(router.urls)),
    path('categories/<slug:slug>/', CategoryRetrieveAPIView.as_view(), name='category-detail'),
    path('parent/categories/', ParentCategoryListAPIView.as_view(), name='parent-categories'),

    path('magaria/', ProductListAPIViewRame.as_view(), name='parent-categories'),

    path('load-products/',         LoadProductsFixtures.as_view(),     name='load-products'),

    path('populate-media/',         CreateProductMedia.as_view(),     name='populate-product-media'),

]