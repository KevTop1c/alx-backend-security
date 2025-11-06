from datetime import timedelta
import logging
from celery import shared_task
from django.utils import timezone
from django.db.models import Count
from .models import RequestLog, SuspiciousIP, BlockedIP

logger = logging.getLogger(__name__)


# pylint: disable=no-member
@shared_task
def detect_anomalies():
    """
    Celery task to detect suspicious IP addresses based on:
    1. High request volume (>100 requests/hour)
    2. Accessing sensitive paths (e.g., /admin, /login)

    Runs hourly to flag suspicious IPs.
    """
    logger.info("Starting anomaly detection task...")

    # Time range: last hour
    one_hour_ago = timezone.now() - timedelta(hours=1)

    # Sensitive paths to monitor
    sensitive_paths = ["/admin", "/login", "/register", "/api"]

    flagged_count = 0

    # 1. Detect high-volume IPs (>100 requests/hour)
    high_volume_ips = (
        RequestLog.objects.filter(timestamp__gte=one_hour_ago)
        .values("ip_address")
        .annotate(request_count=Count("id"))
        .filter(request_count__gt=100)
    )

    for item in high_volume_ips:
        ip_address = item["ip_address"]
        request_count = item["request_count"]

        # Check if already flagged recently (within last 24 hours)
        recent_flag = SuspiciousIP.objects.filter(
            ip_address=ip_address,
            flagged_at__gte=timezone.now() - timedelta(hours=24),
            is_resolved=False,
        ).exists()

        # Check if already blocked
        is_blocked = BlockedIP.objects.filter(
            ip_address=ip_address, is_active=True
        ).exists()

        if not recent_flag and not is_blocked:
            SuspiciousIP.objects.create(
                ip_address=ip_address,
                reason=f"High request volume: {request_count} requests in the last hour",
                request_count=request_count,
            )
            flagged_count += 1
            logger.warning(
                "Flagged IP %s for high volume: %s requests/hour",
                ip_address,
                request_count,
            )

    # 2. Detect IPs accessing sensitive paths excessively
    for path_prefix in sensitive_paths:
        sensitive_ips = (
            RequestLog.objects.filter(
                timestamp__gte=one_hour_ago, path__startswith=path_prefix
            )
            .values("ip_address")
            .annotate(request_count=Count("id"))
            .filter(request_count__gt=20)  # More than 20 attempts on sensitive paths
        )

        for item in sensitive_ips:
            ip_address = item["ip_address"]
            request_count = item["request_count"]

            # Check if already flagged recently
            recent_flag = SuspiciousIP.objects.filter(
                ip_address=ip_address,
                flagged_at__gte=timezone.now() - timedelta(hours=24),
                is_resolved=False,
            ).exists()

            # Check if already blocked
            is_blocked = BlockedIP.objects.filter(
                ip_address=ip_address, is_active=True
            ).exists()

            if not recent_flag and not is_blocked:
                SuspiciousIP.objects.create(
                    ip_address=ip_address,
                    reason=f"Excessive access to sensitive path '{path_prefix}': {request_count} requests in the last hour",
                    request_count=request_count,
                )
                flagged_count += 1
                logger.warning(
                    "Flagged IP %s for sensitive path access: %s requests to %s",
                    ip_address,
                    request_count,
                    path_prefix,
                )

    # 3. Detect failed login attempts (optional - requires tracking failed logins)
    failed_login_ips = (
        RequestLog.objects.filter(timestamp__gte=one_hour_ago, path="/login")
        .values("ip_address")
        .annotate(request_count=Count("id"))
        .filter(request_count__gt=10)  # More than 10 login attempts
    )

    for item in failed_login_ips:
        ip_address = item["ip_address"]
        request_count = item["request_count"]

        recent_flag = SuspiciousIP.objects.filter(
            ip_address=ip_address,
            flagged_at__gte=timezone.now() - timedelta(hours=24),
            is_resolved=False,
            reason__contains="login",
        ).exists()

        is_blocked = BlockedIP.objects.filter(
            ip_address=ip_address, is_active=True
        ).exists()

        if not recent_flag and not is_blocked:
            SuspiciousIP.objects.create(
                ip_address=ip_address,
                reason=f"Possible brute force attack: {request_count} login attempts in the last hour",
                request_count=request_count,
            )
            flagged_count += 1
            logger.warning(
                "Flagged IP %s for possible brute force: %s login attempts",
                ip_address,
                request_count,
            )

    logger.info(
        "Anomaly detection completed. Flagged %s suspicious IPs.", flagged_count
    )

    return {"flagged_count": flagged_count, "timestamp": timezone.now().isoformat()}


@shared_task
def cleanup_old_logs():
    """
    Optional task to clean up old request logs.
    Keeps logs for 30 days.
    """
    thirty_days_ago = timezone.now() - timedelta(days=30)
    deleted_count, _ = RequestLog.objects.filter(timestamp__lt=thirty_days_ago).delete()
    logger.info("Cleaned up %s old request logs", deleted_count)
    return deleted_count


@shared_task
def auto_block_suspicious_ips():
    """
    Optional task to automatically block IPs that have been flagged multiple times.
    """
    # Find IPs flagged more than 3 times in the last 24 hours
    twenty_four_hours_ago = timezone.now() - timedelta(hours=24)

    suspicious_ips = (
        SuspiciousIP.objects.filter(
            flagged_at__gte=twenty_four_hours_ago, is_resolved=False
        )
        .values("ip_address")
        .annotate(flag_count=Count("id"))
        .filter(flag_count__gte=3)
    )

    blocked_count = 0
    for item in suspicious_ips:
        ip_address = item["ip_address"]
        flag_count = item["flag_count"]

        # Check if already blocked
        already_blocked = BlockedIP.objects.filter(
            ip_address=ip_address, is_active=True
        ).exists()

        if not already_blocked:
            BlockedIP.objects.create(
                ip_address=ip_address,
                reason=f"Automatically blocked: Flagged {flag_count} times in 24 hours",
                is_active=True,
            )

            # Mark all flags for this IP as resolved
            SuspiciousIP.objects.filter(
                ip_address=ip_address, is_resolved=False
            ).update(
                is_resolved=True,
                resolved_at=timezone.now(),
                notes="Automatically blocked by system",
            )

            blocked_count += 1
            logger.warning("Auto-blocked IP %s after %s flags", ip_address, flag_count)

    logger.info("Auto-blocked %s IPs", blocked_count)
    return blocked_count
