import logging
import requests
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

    BLOCKED_IP_CACHE_PREFIX = "blocked_ip_"
    GEOLOCATION_CACHE_PREFIX = "geolocation_"
    BLOCKED_IP_CACHE_TIMEOUT = 300  # 5 minutes
    GEOLOCATION_CACHE_TIMEOUT = 86400  # 24 hours

    # Geolocation API endpoint (no API key required)
    GEOLOCATION_API_URL = "http://ip-api.com/json/{ip}?fields=status,country,city"

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

        # Get geolocation data
        country, city = self.get_geolocation(ip_address)

        try:
            # Save request log to database
            RequestLog.objects.create(
                ip_address=ip_address,
                path=path,
                country=country,
                city=city,
            )
            location_info = f"{city}, {country}" if city and country else "Unknown"
            logger.info(
                "Request logged: IP=%s, Location=%s, Path=%s",
                ip_address,
                location_info,
                path,
            )
        except Exception as e:
            logger.error("Failed to log request: %s", e)

        return None

    def get_geolocation(self, ip_address):
        """
        Get geolocation data (country and city) for an IP address.
        Uses caching to store results for 24 hours.
        Uses ip-api.com free API (45 requests per minute limit).
        """
        # Skip geolocation for local/private IPs
        if self.is_private_ip(ip_address):
            return None, None

        cache_key = f"{self.GEOLOCATION_CACHE_PREFIX}{ip_address}"

        # Check cache first
        cached_data = cache.get(cache_key)
        if cached_data is not None:
            return cached_data

        # Fetch geolocation data from API
        try:
            url = self.GEOLOCATION_API_URL.format(ip=ip_address)
            response = requests.get(url, timeout=2)

            if response.status_code == 200:
                data = response.json()

                if data.get("status") == "success":
                    country = data.get("country")
                    city = data.get("city")
                    result = (country, city)

                    # Cache the result for 24 hours
                    cache.set(cache_key, result, self.GEOLOCATION_CACHE_TIMEOUT)

                    return result

            # If API call failed, cache empty result
            logger.warning(
                "Geolocation API returned status %s for IP %s",
                response.status_code,
                ip_address,
            )
            cache.set(cache_key, (None, None), self.GEOLOCATION_CACHE_TIMEOUT)
            return None, None
        except requests.exceptions.Timeout:
            logger.warning("Geolocation API timeout for IP %s", ip_address)
            cache.set(cache_key, (None, None), 3600)  # Cache for 1 hour on timeout
            return None, None
        except Exception as e:
            logger.error("Failed to get geolocation for IP %s: %s", ip_address, e)
            cache.set(cache_key, (None, None), 3600)  # Cache for 1 hour on error
            return None, None

    def is_private_ip(self, ip_address):
        """
        Check if an IP address is private/local.
        """
        if not ip_address:
            return True

        # Check for localhost
        if ip_address in ["127.0.0.1", "::1", "localhost"]:
            return True

        # Check for private IPv4 ranges
        parts = ip_address.split(".")
        if len(parts) == 4:
            try:
                first_octet = int(parts[0])
                second_octet = int(parts[1])

                # 10.0.0.0/8
                if first_octet == 10:
                    return True
                # 172.16.0.0/12
                if first_octet == 172 and 16 <= second_octet <= 31:
                    return True
                # 192.168.0.0/16
                if first_octet == 192 and second_octet == 168:
                    return True
            except ValueError:
                pass

        return False

    def is_ip_blocked(self, ip_address):
        """
        Check if an IP address is in the blocklist.
        Uses caching to minimize database queries.
        """
        cache_key = f"{self.BLOCKED_IP_CACHE_PREFIX}{ip_address}"

        # Check cache first
        cached_result = cache.get(cache_key)
        if cached_result is not None:
            return cached_result

        # Query database
        is_blocked = BlockedIP.objects.filter(
            ip_address=ip_address, is_active=True
        ).exists()

        # Cache the result
        cache.set(cache_key, is_blocked, self.BLOCKED_IP_CACHE_TIMEOUT)

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
