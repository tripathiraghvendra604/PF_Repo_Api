from rest_framework import permissions


class IsAccountOwner(permissions.BasePermission):
    message = 'You must be the owner of this Account!'
    def has_object_permission(self, request, view, account):
        if request.user:
            return account == request.user
        return False