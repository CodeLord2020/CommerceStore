from rest_framework import permissions



from rest_framework.permissions import BasePermission

class IsAdminOrReadOnly(BasePermission):
    """
    Custom permission to allow read-only access to non-admin users,
    but only allow admins to create or delete.
    """

    def has_permission(self, request, view):
        # Allow any user to access list and retrieve actions (GET requests)
        if request.method in ['GET', 'HEAD', 'OPTIONS']:
            return True
        # Allow only admin users to create and delete
        return request.user and request.user.is_staff

    def has_object_permission(self, request, view, obj):
        # Allow read-only permissions for non-admin users on individual objects
        if request.method in ['GET', 'HEAD', 'OPTIONS']:
            return True
        # Allow only admin users to modify or delete objects
        return request.user and request.user.is_staff



class IsOwnerOrReadOnly(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.method in permissions.SAFE_METHODS:
            return True
        return obj.owner == request.user