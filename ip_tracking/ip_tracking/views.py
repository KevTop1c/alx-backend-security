from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django_ratelimit.decorators import ratelimit
from .models import RequestLog


# pylint: disable=no-member
# pylint: disable=unused-argument
def rate_limit_handler(request, exception):
    """
    Custom handler for rate limit exceeded responses.
    """
    return render(
        request,
        "ip_tracking/rate_limit_exceeded.html",
        {"retry_after": getattr(exception, "retry_after", 60)},
        status=429,
    )


@ratelimit(key="ip", rate="5/m", method="POST", block=True)
@ratelimit(key="user_or_ip", rate="10/m", method="POST", block=True)
@require_http_methods(["GET", "POST"])
def login_view(request):
    """
    Login view with rate limiting.
    - Anonymous users: 5 requests per minute (by IP)
    - Authenticated users: 10 requests per minute (by user or IP)
    """
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        user = authenticate(request, username=username, password=password)
        if user is not None:
            auth_login(request, user)
            return redirect("dashboard")
        else:
            return render(
                request,
                "ip_tracking/login.html",
                {"error": "Invalid username or password"},
            )

    return render(request, "ip_tracking/login.html")


@ratelimit(key="ip", rate="5/m", method="POST", block=True)
@ratelimit(key="user_or_ip", rate="10/m", method="POST", block=True)
@require_http_methods(["GET", "POST"])
def register_view(request):
    """
    Registration view with rate limiting.
    - Anonymous users: 5 requests per minute (by IP)
    - Authenticated users: 10 requests per minute (by user or IP)
    """
    if request.method == "POST":
        # Registration logic here
        return render(
            request,
            "ip_tracking/register.html",
            {"success": "Registration successful! Please login."},
        )

    return render(request, "ip_tracking/register.html")


@ratelimit(key="ip", rate="20/m", method="GET", block=True)
@ratelimit(key="user_or_ip", rate="50/m", method="GET", block=True)
def api_endpoint(request):
    """
    API endpoint with rate limiting.
    - Anonymous users: 20 requests per minute
    - Authenticated users: 50 requests per minute
    """
    data = {"status": "success", "message": "API endpoint accessed successfully"}
    return JsonResponse(data)


@login_required
@ratelimit(key="user", rate="100/h", method="GET", block=True)
def dashboard(request):
    """
    Dashboard view with rate limiting.
    Requires authentication and limits to 100 requests per hour per user.
    """
    # Get recent request logs for the current user's IP
    client_ip = get_client_ip(request)
    recent_logs = RequestLog.objects.filter(ip_address=client_ip)[:10]

    context = {
        "user": request.user,
        "recent_logs": recent_logs,
        "client_ip": client_ip,
    }
    return render(request, "ip_tracking/dashboard.html", context)


@login_required
def logout_view(request):
    """
    Logout view (no rate limiting needed).
    """
    auth_logout(request)
    return redirect("login")


def get_client_ip(request):
    """
    Extract the client's IP address from the request.
    """
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        ip = x_forwarded_for.split(",")[0].strip()
    else:
        ip = request.META.get("REMOTE_ADDR")
    return ip


# Example: Rate limit by custom key (e.g., API key in header)
@ratelimit(key="header:X-API-Key", rate="100/h", method="POST", block=True)
def api_with_key(request):
    """
    API endpoint rate-limited by API key in header.
    """
    return JsonResponse({"status": "success"})
