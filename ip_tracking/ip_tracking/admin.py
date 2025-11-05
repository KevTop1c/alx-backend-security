from django.contrib import admin
from .models import RequestLog,BlockedIP


@admin.register(RequestLog)
class RequestLogAdmin(admin.ModelAdmin):
    """Admin view"""

    list_display = ("ip_address", "path", "timestamp")
    list_filter = ("timestamp",)
    search_fields = ("ip_address", "path")
    readonly_fields = ("ip_address", "path", "timestamp")


@admin.register(BlockedIP)
class BlockedIPAdmin(admin.ModelAdmin):
    list_display = ("ip_address", "is_active", "created_at", "reason_preview")
    list_filter = ("is_active", "created_at")
    search_fields = ("ip_address", "reason")
    readonly_fields = ("created_at",)
    date_hierarchy = "created_at"

    fieldsets = (
        ("IP Information", {"fields": ("ip_address", "is_active")}),
        ("Details", {"fields": ("reason", "created_at")}),
    )

    def reason_preview(self, obj):
        """Show a preview of the reason"""
        if obj.reason:
            return obj.reason[:50] + "..." if len(obj.reason) > 50 else obj.reason
        return "No reason provided"

    reason_preview.short_description = "Reason"

    actions = ["activate_blocks", "deactivate_blocks"]

    def activate_blocks(self, request, queryset):
        """Activate selected IP blocks"""
        count = queryset.update(is_active=True)
        self.message_user(request, f"{count} IP block(s) activated.")

    activate_blocks.short_description = "Activate selected IP blocks"

    def deactivate_blocks(self, request, queryset):
        """Deactivate selected IP blocks"""
        count = queryset.update(is_active=False)
        self.message_user(request, f"{count} IP block(s) deactivated.")

    deactivate_blocks.short_description = "Deactivate selected IP blocks"
