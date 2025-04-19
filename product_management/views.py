from django.db import transaction
from django.db.models import Prefetch, Max
from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_page

from rest_framework import viewsets, generics
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.exceptions import APIException
from rest_framework.throttling import AnonRateThrottle, UserRateThrottle
from rest_framework.filters import OrderingFilter
from django_filters.rest_framework import DjangoFilterBackend

from drf_spectacular.utils import (
    extend_schema, extend_schema_view, OpenApiParameter, OpenApiExample, OpenApiTypes
)
import logging

from .models import Product, ProductMedia, Category
from .serializers import (
    ProductWriteSerializer,
    ProductRetrieveSerializer,
    CategorySerializer,
    ProductListSerializer,
    SimpleCategorySerializer, 
    ProductUpdateRetrieveSerializer
)
from .filters import ProductFilter
from .pagination import ProductPagination
from users.authentication import JWTAuthentication
from .permissions import IsOwnerOrAdmin
from utils.product_search import apply_full_text_search, apply_active_filter

logger = logging.getLogger("rest_framework")


# -------------------------------------------------
# Product CRUD viewSet
# -------------------------------------------------
@extend_schema_view(
    list=extend_schema(
        summary="List Products",
        description=(
            "Retrieve a paginated list of all active products. Supports filtering by price, condition, "
            "category, and ordering by specified fields. Uses optimized queries with related seller, media, and "
            "category data. Additionally, supports full-text search with relevance ranking by providing a `q` parameter, "
            "and optionally filtering by owner using the `owner` parameter."
        ),
        parameters=[
            OpenApiParameter(
                name="q",
                type=OpenApiTypes.STR,
                location=OpenApiParameter.QUERY,
                description="Full-text search parameter."
            ),
            OpenApiParameter(
                name="owner",
                type=OpenApiTypes.INT,
                location=OpenApiParameter.QUERY,
                description="Filter products by owner (user) ID."
            )
        ]
    ),
    retrieve=extend_schema(
        summary="Retrieve Product",
        description=(
            "Retrieve detailed information for a single product by its slug. Returned data includes nested images, "
            "a category breadcrumb, and seller details."
        )
    ),
    create=extend_schema(
        summary="Create Product",
        description=(
            "Create a new product. The authenticated user is automatically set as the seller. Required fields include "
            "name, description, price, stock, condition, and category. \n\n"
            "**Images:**\n"
            "- Images must be submitted as part of a multipart/form-data request using the key `images`.\n"
            "- You must upload at least one image and no more than six images.\n"
            "- Optionally, use the query parameter `featured_index` (an integer, default is 0) to indicate which "
            "uploaded image should be marked as featured.\n\n"
            "For example, if you upload three images and set `featured_index=1`, the second image will be designated "
            "as the featured image."
        ),
        parameters=[
            OpenApiParameter(
                name="featured_index",
                type=OpenApiTypes.INT,
                location=OpenApiParameter.QUERY,
                required=False,
                description="Index of the image to mark as featured (default is 0)."
            )
        ],
        examples=[
            OpenApiExample(
                name="Create Product Example",
                description="Example payload for creating a product. Ensure to send images as files via multipart/form-data.",
                value={
                    "name": "Wireless Headphones",
                    "description": "Over-ear noise-cancelling headphones.",
                    "price": 199.99,
                    "stock": 25,
                    "condition": "new",
                    "category": 1,
                    "featured_index": 1
                },
                request_only=True,
            )
        ]
    ),
    update=extend_schema(
        summary="Update Product",
        request=ProductWriteSerializer,
        responses=ProductRetrieveSerializer,
        description=(
            "Update an existing product along with its images. If no `images_metadata` key is provided in the request, "
            "the existing images will remain unchanged. \n\n"
            "When updating images, supply an `images_metadata` JSON array as part of the request body. Each element in the "
            "array must be a dictionary following these rules:\n\n"
            " - **Updating an Existing Image:** Include an `id` key with the image's ID and an optional `is_feature` boolean to set its featured status.\n\n"
            " - **Adding a New Image:** Include an `index` key (a zero-based position indicating which file to use from the uploaded files) "
            "and an optional `is_feature` flag.\n\n"
            "Any existing image not referenced in the provided metadata will be deleted. Also, ensure that the number of new image "
            "files uploaded matches the number of metadata items that require new files."
        ),
        examples=[
            OpenApiExample(
                name="Update Product Example",
                description=(
                    "Example payload for updating a product:\n"
                    "```\n"
                    '[{"id": 10, "is_feature": false}, {"index": 0, "is_feature": true}]\n'
                    "```\n"
                    "This example updates an existing image (with ID 10, not featured) and creates a new image (from the first uploaded file), marked as featured."
                ),
                value={
                    "name": "Updated Product Name",
                    "price": 149.99,
                    "images_metadata": '[{"id": 10, "is_feature": false}, {"index": 0, "is_feature": true}]'
                },
                request_only=True,
            )
        ]
    ),
    partial_update=extend_schema(
        summary="Partial Update Product",
        description="Partially update a product (allowed for the product owner or an admin)."
    ),
    destroy=extend_schema(
        summary="Delete Product",
        description=(
            "Delete a product along with its associated media files in an atomic transaction. "
            "This operation does not check for active cart associations."
        )
    )
)
class ProductViewSet(viewsets.ModelViewSet):
    """
    API endpoint for managing products.

    GET requests are public (only active products are returned) and
    enriched with related seller, media, and breadcrumb category data.
    POST/PUT/PATCH/DELETE require JWT authentication; only the product owner or an admin can modify.

    Additional enhancements:
      - **Caching:** The list view is cached for 5 minutes.
      - **Ordering:** Supports ordering by fields such as 'price', 'created_at', 'units_sold'.
      - **Throttling:** Rate limiting is applied for both anonymous and authenticated users.
      - **Search:** Full-text search using PostgreSQL, with optional owner-based filtering.
    """

    queryset = Product.objects.all()
    authentication_classes = [JWTAuthentication]
    lookup_field = 'slug'
    filter_backends = [DjangoFilterBackend, OrderingFilter]
    filterset_class = ProductFilter
    pagination_class = ProductPagination

    # Expose ordering fields for GET queries
    ordering_fields = ['price', 'created_at']
    ordering = ['-created_at']  # Default ordering

    # Apply throttling to all endpoints in this viewset
    throttle_classes = [AnonRateThrottle, UserRateThrottle]

    def get_serializer_class(self):
        # For GET requests, choose serializer based on action
        if self.request and self.request.method == 'GET':
            if self.action == 'retrieve':
                # If the query parameter 'edit' is present, return the update serializer.
                if self.request.query_params.get('edit') == 'true':
                    return ProductUpdateRetrieveSerializer
                return ProductRetrieveSerializer
            elif self.action == 'list':
                return ProductListSerializer
        # For non-GET requests use the write serializer.
        return ProductWriteSerializer

    def get_authenticators(self):
        if self.request and self.request.method == 'GET':
            return []  # Public access for GET requests.
        return [JWTAuthentication()]

    def get_permissions(self):
        if self.request and self.request.method in ['PUT', 'PATCH', 'DELETE']:
            return [IsAuthenticated(), IsOwnerOrAdmin()]
        return [AllowAny()]

    def get_queryset(self):

        if self.request and self.request.method == 'GET' and self.action == 'list':
            queryset = Product.objects.prefetch_related(
                Prefetch('media', queryset=ProductMedia.objects.filter(is_feature=True).only(
                    'id', 'image', 'is_feature', 'created_at', 'product'
                ))
            ).only(
                'id', 'name', 'description', 'slug', 'price', 'stock',
                'condition', 'created_at', 'updated_at', 'is_active', "average_rating", "total_reviews"
            )
        else:
            queryset = Product.objects.select_related(
                'seller', 'category', 'category__parent'
            ).prefetch_related(
                Prefetch('media', queryset=ProductMedia.objects.only(
                    'id', 'image', 'is_feature', 'created_at', 'product'
                ))
            ).only(
                'id', 'name', 'description', 'slug', 'price', 'stock',
                'condition', 'created_at', 'updated_at', 'seller', 'is_active', 'category'
            )

        # Apply active filter.
        queryset = apply_active_filter(queryset, self.request)

        # Apply full-text search (if applicable).
        queryset = apply_full_text_search(queryset, self.request)

        return queryset

    @method_decorator(cache_page(60 * 2, key_prefix="product_management:product_list"), name="list")
    def list(self, request, *args, **kwargs):
        filtered_queryset = self.filter_queryset(self.get_queryset())
        aggregated = filtered_queryset.aggregate(max_price=Max('price'))
        max_price = aggregated.get('max_price') or 0.1

        response = super().list(request, *args, **kwargs)
        response.data['price_range'] = {"min_price": 0.1, "max_price": max_price}

        return response

    def perform_create(self, serializer):
        serializer.save(seller=self.request.user)

    def perform_destroy(self, instance):
        try:
            with transaction.atomic():
                for media in instance.media.all():
                    try:
                        media.image.delete(save=False)
                    except Exception as e:
                        logger.warning(
                            f"Failed to delete image file for ProductMedia ID {media.id}: {str(e)}"
                        )
                    media.delete()
                instance.delete()

        except Exception as e:
            logger.exception(f"Error occurred during product deletion: {str(e)}")
            raise APIException("An error occurred while deleting the product. Please try again later.")
        

class CategoryRetrieveAPIView(generics.RetrieveAPIView):
    """
    API endpoint to retrieve a category and its children recursively.
    The lookup is done by the category slug.
    """
    serializer_class = CategorySerializer
    lookup_field = 'slug'

    def get_queryset(self):
        # Load the category along with multiple levels of children.
        return Category.objects.all().prefetch_related(
            'children', 'children__children', 'children__children__children'
        )

class ParentCategoryListAPIView(generics.ListAPIView):
    """
    API endpoint to retrieve parent categories without nested children.
    This is optimized for cases where child data is not needed.
    """
    serializer_class = SimpleCategorySerializer

    def get_queryset(self):
        # Return only parent categories.
        return Category.objects.filter(parent__isnull=True)



from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from pathlib import Path
import os
import json
import time
import requests
import cloudinary.uploader

class CreateProductMedia(APIView):
    """
    POST to this endpoint will fetch images from Unsplash, upload them to Cloudinary,
    and create ProductMedia objects linked to each product loaded from fixtures.
    """

    def post(self, request):
        # Unsplash configuration
        UNSPLASH_API_URL = "https://api.unsplash.com/search/photos"
        UNSPLASH_ACCESS_KEY = os.environ.get("UNSPLASH_ACCESS_KEY")
        if not UNSPLASH_ACCESS_KEY:
            return Response({'detail': 'Missing UNSPLASH_ACCESS_KEY.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Load fixtures JSON to get product IDs and names
        project_root = Path(settings.BASE_DIR).parent
        fixture_file = project_root / 'fixtures' / 'product_fixtures' / 'product_fixtures.json'
        if not fixture_file.exists():
            return Response(
                {'detail': f'Fixture file not found at {fixture_file}'},
                status=status.HTTP_404_NOT_FOUND
            )

        try:
            with open(fixture_file, 'r', encoding='utf-8') as f:
                products = json.load(f)
        except Exception as e:
            return Response({'detail': f'Error loading fixtures file: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        IMAGES_PER_PRODUCT = 2
        for pf in products:
            product_id = pf.get('id')
            fields = pf.get('fields', {})
            product_name = fields.get('name')
            if not (product_id and product_name):
                continue

            try:
                product = Product.objects.get(pk=product_id)
            except Product.DoesNotExist:
                continue

            # Search Unsplash for product images
            params = {
                'query': product_name,
                'per_page': 5,
                'client_id': UNSPLASH_ACCESS_KEY,
            }
            response = requests.get(UNSPLASH_API_URL, params=params)
            if response.status_code != 200:
                continue
            data = response.json().get('results', [])
            image_urls = [r['urls']['regular'] for r in data]
            if not image_urls:
                continue

            # Choose up to IMAGES_PER_PRODUCT
            chosen = (image_urls * IMAGES_PER_PRODUCT)[:IMAGES_PER_PRODUCT] if len(image_urls) < IMAGES_PER_PRODUCT else image_urls[:IMAGES_PER_PRODUCT]
            for idx, url in enumerate(chosen):
                try:
                    result = cloudinary.uploader.upload(url)
                    secure_url = result.get('secure_url')
                    if not secure_url:
                        continue

                    ProductMedia.objects.create(
                        product=product,
                        image=secure_url,
                        is_feature=(idx == 0)
                    )
                except Exception:
                    continue
            time.sleep(0.5)

        return Response({'detail': 'Product media created.'}, status=status.HTTP_200_OK)