from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from .views import TokenObtainPairView, RegisterView, LogoutView, HasPermissionView

urlpatterns = [
    path('login/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('register/', RegisterView.as_view(), name='auth_register'),
    path('logout/', LogoutView.as_view(), name='auth_logout'),
    path('has_permission/<str:permission>/', HasPermissionView.as_view(), name='has_permission'),
]