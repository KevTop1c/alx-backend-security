from django.db import models


# pylint: disable=no-member
class RequestLog(models.Model):
    """
    Model to store request logs with IP address, timestamp, and path.
    """

    ip_address = models.GenericIPAddressField(
        help_text="IP address of the client making the request",
    )
    timestamp = models.DateTimeField(
        auto_now_add=True,
        help_text="Time when request was made",
    )
    path = models.CharField(
        max_length=2048,
        help_text="URL path for the request",
    )
    country = models.CharField(
        max_length=100,
        blank=True,
        null=True,
        help_text="Country of the IP address",
    )
    city = models.CharField(
        max_length=100,
        blank=True,
        null=True,
        help_text="City of the IP address",
    )

    class Meta:
        ordering = ["-timestamp"]
        verbose_name = "Request Log"
        verbose_name_plural = "Request Logs"
        indexes = [
            models.Index(fields=["-timestamp"]),
            models.Index(fields=["ip_address"]),
            models.Index(fields=["country"]),
            models.Index(fields=["city"]),
        ]

    def __str__(self):
        location = (
            f"{self.city}, {self.country}"
            if self.city and self.country
            else "Unknown location"
        )
        return f"{self.ip_address} ({location}) - {self.path} at {self.timestamp}"


class BlockedIP(models.Model):
    """
    Model to store blocked IP addresses.
    """

    ip_address = models.GenericIPAddressField(
        unique=True,
        help_text="IP address to block",
    )
    reason = models.TextField(
        blank=True,
        null=True,
        help_text="Reason for blocking this IP address",
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        help_text="When this IP was blocked",
    )
    is_active = models.BooleanField(
        default=True,
        help_text="Whether this block is currently active",
    )

    class Meta:
        verbose_name = "Blocked IP"
        verbose_name_plural = "Blocked IPs"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["ip_address", "is_active"]),
        ]

    def __str__(self):
        status = "Active" if self.is_active else "Inactive"
        return f"{self.ip_address} ({status})"


class SuspiciousIP(models.Model):
    """
    Model to store suspicious IP addresses flagged by anomaly detection.
    """

    ip_address = models.GenericIPAddressField(
        help_text="Suspicious IP address",
    )
    reason = models.TextField(
        help_text="Reason why this IP was flagged as suspicious",
    )
    flagged_at = models.DateTimeField(
        auto_now_add=True,
        help_text="When this IP was flagged",
    )
    request_count = models.IntegerField(
        default=0,
        help_text="Number of requests in the detection period",
    )
    is_resolved = models.BooleanField(
        default=False,
        help_text="Whether this flag has been reviewed and resolved",
    )
    resolved_at = models.DateTimeField(
        blank=True,
        null=True,
        help_text="When this flag was resolved",
    )
    notes = models.TextField(
        blank=True,
        null=True,
        help_text="Admin notes about this flag",
    )

    class Meta:
        verbose_name = "Suspicious IP"
        verbose_name_plural = "Suspicious IPs"
        ordering = ["-flagged_at"]
        indexes = [
            models.Index(fields=["ip_address"]),
            models.Index(fields=["is_resolved"]),
            models.Index(fields=["-flagged_at"]),
        ]

    def __str__(self):
        status = "Resolved" if self.is_resolved else "Unresolved"
        return f"{self.ip_address} - {status} ({self.flagged_at.strftime('%Y-%m-%d %H:%M')})"
