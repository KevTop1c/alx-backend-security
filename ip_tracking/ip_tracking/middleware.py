import logging
from django.utils.deprecation import MiddlewareMixin
from .models import RequestLog

logger = logging.getLogger(__name__)


# pylint: disable=broad-exception-caught
# pylint: disable=no-member
class IPTrackingMiddleware(MiddlewareMixin):
    """
    Middleware to log IP address, timestamp, and path of every incoming request.
    """

    def process_request(self, request):
        """Process each incoming request and log its details"""

        # Get the client's IP address
        ip_address = self.get_client_ip(request)

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
