import logging
from django.utils.deprecation import MiddlewareMixin
from django.http import HttpResponseForbidden
from django.core.cache import cache
from .models import RequestLog, BlockedIP

logger = logging.getLogger(__name__)


# pylint: disable=broad-exception-caught
# pylint: disable=no-member
class IPTrackingMiddleware(MiddlewareMixin):
    """
    Middleware to log IP address, timestamp, and path of every incoming request.
    Also blocks requests from blacklisted IP addresses.
    """

    CACHE_KEY_PREFIX = "blocked_ip_"
    CACHE_TIMEOUT = 300  # 5 minutes

    def process_request(self, request):
        """Process each incoming request and log its details"""

        # Get the client's IP address
        ip_address = self.get_client_ip(request)

        # Check if IP is blocked
        if self.is_ip_blocked(ip_address):
            logger.warning(
                "Blocked request from IP=%s, Path=%s", ip_address, request.path
            )
            return HttpResponseForbidden(
                "<h1>403 Forbidden</h1><p>Your IP address has been blocked.</p>"
            )

        # Get the request path
        path = request.path

        try:
            # Save request log to database
            RequestLog.objects.create(
                ip_address=ip_address,
                path=path,
            )
            logger.info("Request logged: IP=%s, Path=%s", ip_address, path)
        except Exception as e:
            logger.error("Failed to log request: %s", e)

        return None

    def is_ip_blocked(self, ip_address):
        """
        Check if an IP address is in the blocklist.
        Uses caching to minimize database queries.
        """
        cache_key = f"{self.CACHE_KEY_PREFIX}{ip_address}"

        # Check cache first
        cached_result = cache.get(cache_key)
        if cached_result is not None:
            return cached_result

        # Query database
        is_blocked = BlockedIP.objects.filter(
            ip_address=ip_address, is_active=True
        ).exists()

        # Cache the result
        cache.set(cache_key, is_blocked, self.CACHE_TIMEOUT)

        return is_blocked

    def get_client_ip(self, request):
        """
        Extract the client's IP address from the request.
        Handles proxy headers like X-Forwarded-For.
        """
        x_forward_for = request.META.get("HTTP_X_FORWARD_FOR")
        if x_forward_for:
            # X-Forwarded-For can contain multiple IPs, get the first one
            ip = x_forward_for.split(",")[0].strip()
        else:
            ip = request.META.get("REMOTE_ADDR")
        return ip
