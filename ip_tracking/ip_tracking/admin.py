from django.contrib import admin
from .models import RequestLog


@admin.register(RequestLog)
class RequestLogAdmin(admin.ModelAdmin):
    """Admin view"""
    list_display = ("ip_address", "path", "timestamp")
    list_filter = ("timestamp",)
    search_fields = ("ip_address", "path")
    readonly_fields = ("ip_address", "path", "timestamp")
