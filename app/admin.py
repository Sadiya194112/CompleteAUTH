from django.contrib import admin
from .models import *


class UserAdmin(admin.ModelAdmin):
    list_display = ['id', 'email', 'is_verified']

admin.site.register(User, UserAdmin)