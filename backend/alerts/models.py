from django.db import models
from django.contrib.auth.models import User
from monitors.models import Monitor


class AlertEvent(models.Model):
    TYPE_ENDPOINT_DOWN = 'endpoint_down'
    TYPE_REPEATED_FAILURE = 'repeated_failure'
    TYPE_LATENCY_WARNING = 'latency_warning'
    TYPE_LATENCY_FAILURE = 'latency_failure'
    TYPE_RECOVERY = 'recovery'

    TYPE_CHOICES = [
        (TYPE_ENDPOINT_DOWN, 'Endpoint Down'),
        (TYPE_REPEATED_FAILURE, 'Repeated Failure'),
        (TYPE_LATENCY_WARNING, 'Latency Warning'),
        (TYPE_LATENCY_FAILURE, 'Latency Failure'),
        (TYPE_RECOVERY, 'Recovery'),
    ]

    SEVERITY_INFO = 'info'
    SEVERITY_WARNING = 'warning'
    SEVERITY_CRITICAL = 'critical'

    SEVERITY_CHOICES = [
        (SEVERITY_INFO, 'Info'),
        (SEVERITY_WARNING, 'Warning'),
        (SEVERITY_CRITICAL, 'Critical'),
    ]

    STATE_ACTIVE = 'active'
    STATE_RESOLVED = 'resolved'

    STATE_CHOICES = [
        (STATE_ACTIVE, 'Active'),
        (STATE_RESOLVED, 'Resolved'),
    ]

    monitor = models.ForeignKey(Monitor, on_delete=models.CASCADE, related_name='alerts', db_index=True)
    alert_type = models.CharField(max_length=40, choices=TYPE_CHOICES, db_index=True)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default=SEVERITY_WARNING)
    state = models.CharField(max_length=20, choices=STATE_CHOICES, default=STATE_ACTIVE, db_index=True)
    triggered_at = models.DateTimeField(auto_now_add=True, db_index=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    description = models.TextField()
    consecutive_count = models.PositiveIntegerField(default=1)

    class Meta:
        ordering = ['-triggered_at']
        indexes = [
            models.Index(fields=['monitor', 'state', '-triggered_at']),
            models.Index(fields=['state', '-triggered_at']),
        ]

    def __str__(self):
        return f"[{self.severity.upper()}] {self.monitor.name}: {self.get_alert_type_display()} ({self.state})"


class NotificationConfig(models.Model):
    CHANNEL_EMAIL = 'email'
    CHANNEL_WEBHOOK = 'webhook'

    CHANNEL_CHOICES = [
        (CHANNEL_EMAIL, 'Email Notification'),
        (CHANNEL_WEBHOOK, 'HTTP Webhook'),
    ]

    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notification_configs', db_index=True)
    channel = models.CharField(max_length=30, choices=CHANNEL_CHOICES, default=CHANNEL_EMAIL)
    enabled = models.BooleanField(default=True)
    target = models.CharField(max_length=500, help_text="Destination email address or Webhook URL")
    secret_token = models.CharField(max_length=255, blank=True, default='', help_text="Bearer token or signing secret")
    notify_on_failure = models.BooleanField(default=True)
    notify_on_latency = models.BooleanField(default=True)
    notify_on_recovery = models.BooleanField(default=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.owner.username} - {self.channel} ({self.target})"
