from django.core.management.base import BaseCommand, CommandError
from django.core.cache import cache
from ip_tracking.models import BlockedIP


# pylint: disable=no-member
class Command(BaseCommand):
    """Custom IP commands"""
    help = "Add or remove IP addresses from the blocklist"

    def add_arguments(self, parser):
        parser.add_argument(
            "ip_address",
            type=str,
            help="IP address to block or unblock",
        )
        parser.add_argument(
            "--reason",
            type=str,
            default="",
            help="Reason for blocking this IP address",
        )
        parser.add_argument(
            "--unblock",
            action="store_true",
            help="Unblock the IP address instead of blocking it",
        )
        parser.add_argument(
            "--list",
            action="store_true",
            help="List all blocked IP addresses",
        )

    def handle(self, *args, **options):
        # Handle list command
        if options["list"]:
            self.list_blocked_ips()
            return

        ip_address = options["ip_address"]
        reason = options["reason"]
        unblock = options["unblock"]

        if unblock:
            self.unblock_ip(ip_address)
        else:
            self.block_ip(ip_address, reason)

    def block_ip(self, ip_address, reason):
        """
        Add an IP address to the blocklist.
        """
        try:
            blocked_ip, created = BlockedIP.objects.get_or_create(
                ip_address=ip_address, defaults={"reason": reason, "is_active": True}
            )

            if created:
                self.stdout.write(
                    self.style.SUCCESS(f"Successfully blocked IP: {ip_address}")
                )
            else:
                # If it exists but was inactive, reactivate it
                if not blocked_ip.is_active:
                    blocked_ip.is_active = True
                    blocked_ip.reason = reason if reason else blocked_ip.reason
                    blocked_ip.save()
                    self.stdout.write(
                        self.style.SUCCESS(f"Reactivated block for IP: {ip_address}")
                    )
                else:
                    self.stdout.write(
                        self.style.WARNING(
                            f"IP address {ip_address} is already blocked"
                        )
                    )

            # Clear cache for this IP
            self.clear_ip_cache(ip_address)

        except Exception as e:
            raise CommandError(f"Error blocking IP {ip_address}: {str(e)}") from e

    def unblock_ip(self, ip_address):
        """
        Remove an IP address from the blocklist.
        """
        try:
            blocked_ip = BlockedIP.objects.get(ip_address=ip_address)
            blocked_ip.is_active = False
            blocked_ip.save()

            self.stdout.write(
                self.style.SUCCESS(f"Successfully unblocked IP: {ip_address}")
            )

            # Clear cache for this IP
            self.clear_ip_cache(ip_address)

        except BlockedIP.DoesNotExist:
            self.stdout.write(
                self.style.WARNING(f"IP address {ip_address} is not in the blocklist")
            )
        except Exception as e:
            raise CommandError(f"Error unblocking IP {ip_address}: {str(e)}") from e

    def list_blocked_ips(self):
        """
        List all blocked IP addresses.
        """
        blocked_ips = BlockedIP.objects.filter(is_active=True).order_by("-created_at")

        if not blocked_ips.exists():
            self.stdout.write(
                self.style.WARNING("No IP addresses are currently blocked")
            )
            return

        self.stdout.write(self.style.SUCCESS("\nBlocked IP Addresses:"))
        self.stdout.write("-" * 80)

        for blocked_ip in blocked_ips:
            reason = blocked_ip.reason or "No reason provided"
            self.stdout.write(
                f"IP: {blocked_ip.ip_address}\n"
                f'  Blocked: {blocked_ip.created_at.strftime("%Y-%m-%d %H:%M:%S")}\n'
                f"  Reason: {reason}\n"
            )

    def clear_ip_cache(self, ip_address):
        """
        Clear the cache for a specific IP address.
        """
        cache_key = f"blocked_ip_{ip_address}"
        cache.delete(cache_key)
