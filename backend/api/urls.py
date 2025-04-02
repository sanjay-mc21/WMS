from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    TaskViewSet, UserViewSet, CustomAuthToken, RegisterView,
    AdminDashboardViewSet, ClientViewSet, ClientDashboardViewSet,
    ReportViewSet, ClientProfileViewSet
)

router = DefaultRouter()
router.register(r'tasks', TaskViewSet)
router.register(r'users', UserViewSet, basename='user')
router.register(r'admin/dashboard', AdminDashboardViewSet, basename='admin-dashboard')
router.register(r'admin/clients', ClientViewSet, basename='admin-clients')
router.register(r'client/dashboard', ClientDashboardViewSet, basename='client-dashboard')
router.register(r'client/profile', ClientProfileViewSet, basename='client-profile')
router.register(r'reports', ReportViewSet, basename='report')

urlpatterns = [
    path('', include(router.urls)),
    path('auth/login/', CustomAuthToken.as_view(), name='auth_token'),
    path('auth/register/', RegisterView.as_view(), name='auth_register'),
] 