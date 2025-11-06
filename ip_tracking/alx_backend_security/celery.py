import os
from celery import Celery
from celery.schedules import crontab

# Set the default Django settings module
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "alx_backend_security.settings")

app = Celery("alx_backend_security")

# Load config from Django settings with CELERY namespace
app.config_from_object("django.conf:settings", namespace="CELERY")

# Auto-discover tasks in all installed apps
app.autodiscover_tasks()

# Configure periodic tasks
app.conf.beat_schedule = {
    "detect-anomalies-hourly": {
        "task": "ip_tracking.tasks.detect_anomalies",
        "schedule": crontab(minute=0),  # Run every hour at minute 0
    },
    "cleanup-old-logs-daily": {
        "task": "ip_tracking.tasks.cleanup_old_logs",
        "schedule": crontab(hour=3, minute=0),  # Run daily at 3 AM
    },
    "auto-block-suspicious-ips-every-6-hours": {
        "task": "ip_tracking.tasks.auto_block_suspicious_ips",
        "schedule": crontab(minute=0, hour="*/6"),  # Run every 6 hours
    },
}


@app.task(bind=True)
def debug_task(self):
    print(f"Request: {self.request!r}")
