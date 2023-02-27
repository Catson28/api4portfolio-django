from django.db import models
from django.contrib.auth.models import Group, Permission

"""
class Role(Group):
    pass

    class Meta:
        verbose_name = 'Role'
        verbose_name_plural = 'Roles'

class Permission(Permission):
    role = models.ManyToManyField(Role, related_name='permissions')

    class Meta:
        verbose_name = 'Permission'
        verbose_name_plural = 'Permissions' 
"""

class Role(models.Model):
    name = models.CharField(max_length=50, unique=True)
    permissions = models.ManyToManyField(
        Permission, related_name='permissions_role')

    def __str__(self):
        return self.name

class Permission(models.Model):
    name = models.CharField(max_length=50, unique=True)
    code = models.CharField(max_length=10, unique=True)
    role = models.ForeignKey(
        Role, on_delete=models.CASCADE, related_name='role_permissions')

    def __str__(self):
        return self.name
