from django.contrib import admin
from .models import RequestLog, BlockedIP, SuspiciousIP


# pylint: disable=no-member
@admin.register(RequestLog)
class RequestLogAdmin(admin.ModelAdmin):
    """IP request log admin view"""

    list_display = ("ip_address", "city", "country", "path", "timestamp")
    list_filter = ("timestamp", "country", "city")
    search_fields = ("ip_address", "path", "country", "city")
    readonly_fields = ("ip_address", "path", "timestamp", "country", "city")
    date_hierarchy = "timestamp"

    fieldsets = (
        ("Request Information", {"fields": ("ip_address", "path", "timestamp")}),
        ("Geolocation", {"fields": ("country", "city")}),
    )


@admin.register(BlockedIP)
class BlockedIPAdmin(admin.ModelAdmin):
    """Blocked IPs admin view"""

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


@admin.register(SuspiciousIP)
class SuspiciousIPAdmin(admin.ModelAdmin):
    """Suspicious IP admin view"""
    list_display = (
        "ip_address",
        "request_count",
        "is_resolved",
        "flagged_at",
        "reason_preview",
    )
    list_filter = ("is_resolved", "flagged_at")
    search_fields = ("ip_address", "reason", "notes")
    readonly_fields = ("ip_address", "reason", "flagged_at", "request_count")
    date_hierarchy = "flagged_at"

    fieldsets = (
        ("IP Information", {"fields": ("ip_address", "request_count")}),
        ("Flag Details", {"fields": ("reason", "flagged_at")}),
        ("Resolution", {"fields": ("is_resolved", "resolved_at", "notes")}),
    )

    def reason_preview(self, obj):
        """Show a preview of the reason"""
        return obj.reason[:60] + "..." if len(obj.reason) > 60 else obj.reason

    reason_preview.short_description = "Reason"

    actions = ["mark_as_resolved", "mark_as_unresolved", "block_selected_ips"]

    def mark_as_resolved(self, request, queryset):
        """Mark selected flags as resolved"""
        from django.utils import timezone

        count = queryset.update(is_resolved=True, resolved_at=timezone.now())
        self.message_user(request, f"{count} flag(s) marked as resolved.")

    mark_as_resolved.short_description = "Mark as resolved"

    def mark_as_unresolved(self, request, queryset):
        """Mark selected flags as unresolved"""
        count = queryset.update(is_resolved=False, resolved_at=None)
        self.message_user(request, f"{count} flag(s) marked as unresolved.")

    mark_as_unresolved.short_description = "Mark as unresolved"

    def block_selected_ips(self, request, queryset):
        """Block all IPs in selected flags"""
        from django.utils import timezone

        blocked_count = 0
        for suspicious_ip in queryset:
            # Check if already blocked
            if not BlockedIP.objects.filter(
                ip_address=suspicious_ip.ip_address, is_active=True
            ).exists():
                BlockedIP.objects.create(
                    ip_address=suspicious_ip.ip_address,
                    reason=f"Blocked from suspicious activity: {suspicious_ip.reason}",
                    is_active=True,
                )
                blocked_count += 1

            # Mark as resolved
            suspicious_ip.is_resolved = True
            suspicious_ip.resolved_at = timezone.now()
            suspicious_ip.notes = "Blocked by admin"
            suspicious_ip.save()

        self.message_user(request, f"{blocked_count} IP(s) blocked and flags resolved.")

    block_selected_ips.short_description = "Block selected IPs"
