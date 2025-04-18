from django.urls import path
from .views import (
    EmailConfirmationView,
    RegisterView,
    LoginUser,
    LogoutUser,
    UserProfileView,
    PasswordResetConfirmView,
    PasswordResetRequestView,
    RefreshAccessTokenView,
    CurrentUserProfileView
)

urlpatterns = [
    path('auth/email_confirmation/', EmailConfirmationView.as_view(), name='email-confirmation'),
    path('auth/register/', RegisterView.as_view(), name='register'),
    path('auth/login/', LoginUser.as_view(), name='login'),
    path('auth/logout/', LogoutUser.as_view(), name='logout'),


    path('reset-password-request/', PasswordResetRequestView.as_view(), name='password-reset-request'),
    path('reset-password-confirm/', PasswordResetConfirmView.as_view(), name='password-reset-confirm'),

    path('token/refresh/', RefreshAccessTokenView.as_view(), name='token_refresh'),

    path("profile/<uuid:user_id>/", UserProfileView.as_view(), name="user-profile"),
    path("profile/current/", CurrentUserProfileView.as_view(), name="current-user-profile"),
]