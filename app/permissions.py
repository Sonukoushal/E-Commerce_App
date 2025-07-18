from rest_framework.permissions import BasePermission

class IsSuperUserOnly(BasePermission):
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated and request.user.is_superuser_custom