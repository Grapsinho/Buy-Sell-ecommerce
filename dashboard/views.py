from django.db.models import Prefetch
from rest_framework import generics, filters, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.pagination import PageNumberPagination
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.views import APIView
from rest_framework.response import Response

from drf_spectacular.utils import extend_schema, OpenApiParameter
from drf_spectacular.types import OpenApiTypes

from product_management.models import Product, ProductMedia
from .dsh_cache import get_cached_recommendations, get_my_product_ids
from .filters import MyProductFilter
from users.authentication import JWTAuthentication
from users.models import User
from .serializers import (
    ProfileSerializer,
    MyProductSerializer,
    RecommendationSerializer
)


@extend_schema(tags=['Profile'], description="Retrieve or update current user's profile.")
class ProfileUpdateRetrieveView(generics.RetrieveUpdateAPIView):
    serializer_class = ProfileSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user


@extend_schema(
    tags=['Profile'],
    parameters=[
        OpenApiParameter('user_id', OpenApiTypes.UUID, OpenApiParameter.PATH),
    ],
    responses={200: ProfileSerializer}
)
class UserProfileView(APIView):
    authentication_classes = [JWTAuthentication]

    permission_classes = [IsAuthenticated]

    def get(self, request, user_id):
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({"detail": "User not found."}, status=status.HTTP_404_NOT_FOUND)

        serializer = ProfileSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)
    

class UserOwnProductPagination(PageNumberPagination):
    page_size = 15
    page_size_query_param = 'page_size'
    max_page_size = 30


@extend_schema(
    tags=['User Own Products'],
    responses={200: MyProductSerializer(many=True)},
    description="List current user's products, paginated."
)
class MyProductListView(generics.ListAPIView):
    """
    GET /dashboard/me/products/
    """
    queryset = Product.objects.none()
    serializer_class = MyProductSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    pagination_class = UserOwnProductPagination
    filter_backends = [filters.OrderingFilter, DjangoFilterBackend]
    ordering_fields = ['price', 'stock', 'units_sold']
    filterset_class = MyProductFilter

    def get_queryset(self):
        # 1) Fetch cached IDs
        ids = get_my_product_ids(self.request.user)
        # 2) Build queryset restricted to those IDs
        qs = (
            Product.objects
                   .filter(id__in=ids)
                   .prefetch_related(
                       Prefetch(
                           'media',
                           queryset=ProductMedia.objects.filter(is_feature=True),
                           to_attr='feature_media'
                       )
                   )
        )
        return qs


@extend_schema(
    tags=['Recommendations'],
    parameters=[
        OpenApiParameter('limit', OpenApiTypes.INT, OpenApiParameter.QUERY, description='Max recommendations (1-10)')
    ],
    responses={200: RecommendationSerializer(many=True)},
    description="Cross-sell recommendations based on cart, wishlist, and purchase history."
)
class RecommendationView(APIView):
    """
    GET /dashboard/me/recommendations/?limit=10
    """
    serializer_class = RecommendationSerializer
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # Pull limit from query params, default to 10
        try:
            limit = int(request.query_params.get('limit', 10))
        except ValueError:
            limit = 10

        # Use the cached recommendation IDs (with 30m TTL + event invalidation)
        recs_qs = get_cached_recommendations(request.user, limit)

        serializer = RecommendationSerializer(recs_qs, many=True, context={'request': request})
        return Response(serializer.data)