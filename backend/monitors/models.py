import urllib.parse
from django.db import models
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError


class Monitor(models.Model):
    STATUS_HEALTHY = 'healthy'
    STATUS_DEGRADED = 'degraded'
    STATUS_FAILING = 'failing'
    STATUS_PENDING = 'pending'

    STATUS_CHOICES = [
        (STATUS_HEALTHY, 'Healthy'),
        (STATUS_DEGRADED, 'Degraded'),
        (STATUS_FAILING, 'Failing'),
        (STATUS_PENDING, 'Pending'),
    ]

    METHOD_CHOICES = [
        ('GET', 'GET'),
        ('POST', 'POST'),
        ('PUT', 'PUT'),
        ('PATCH', 'PATCH'),
        ('DELETE', 'DELETE'),
        ('HEAD', 'HEAD'),
        ('OPTIONS', 'OPTIONS'),
    ]

    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='monitors', db_index=True)
    name = models.CharField(max_length=200, help_text="Friendly label for the monitored endpoint")
    target_url = models.URLField(max_length=1000, help_text="Fully qualified HTTP or HTTPS target URL")
    http_method = models.CharField(max_length=10, choices=METHOD_CHOICES, default='GET')
    request_body = models.TextField(blank=True, default='', help_text="Optional payload body for POST/PUT/PATCH")
    enabled = models.BooleanField(default=True, db_index=True, help_text="Whether background health checks are active")
    check_interval = models.PositiveIntegerField(
        default=60,
        help_text="Frequency of health checks in seconds (e.g., 30, 60, 300)"
    )
    request_timeout = models.PositiveIntegerField(
        default=10,
        help_text="Request timeout ceiling in seconds (1 to 60)"
    )
    expected_status_codes = models.CharField(
        max_length=100,
        default='200-299',
        help_text="Expected HTTP status codes: e.g. '200', '200,201,204', or '200-299'"
    )
    latency_warning_threshold = models.PositiveIntegerField(
        default=500,
        help_text="Response time threshold in ms that triggers degraded warning"
    )
    latency_failure_threshold = models.PositiveIntegerField(
        default=2000,
        help_text="Response time threshold in ms that triggers latency failure"
    )

    # Denormalized latest status tracking for rapid dashboard lookups
    last_checked_at = models.DateTimeField(null=True, blank=True)
    last_status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_PENDING, db_index=True)
    last_response_time_ms = models.FloatField(null=True, blank=True)
    last_status_code = models.IntegerField(null=True, blank=True)
    consecutive_failures = models.PositiveIntegerField(default=0)

    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['owner', 'enabled']),
            models.Index(fields=['owner', 'last_status']),
            models.Index(fields=['enabled', 'last_checked_at']),
        ]

    def __str__(self):
        return f"{self.name} ({self.target_url}) [{self.last_status}]"

    @property
    def hostname(self) -> str:
        try:
            parsed = urllib.parse.urlparse(self.target_url)
            return parsed.netloc or parsed.path
        except Exception:
            return self.target_url

    def clean(self):
        # Validate timeout
        if self.request_timeout < 1 or self.request_timeout > 60:
            raise ValidationError({'request_timeout': 'Request timeout must be between 1 and 60 seconds.'})

        # Validate check_interval
        if self.check_interval < 10 or self.check_interval > 86400:
            raise ValidationError({'check_interval': 'Check interval must be between 10 and 86400 seconds.'})

        # Validate thresholds
        if self.latency_failure_threshold < self.latency_warning_threshold:
            raise ValidationError({
                'latency_failure_threshold': 'Failure threshold cannot be lower than warning threshold.'
            })

    def matches_expected_status(self, status_code: int) -> bool:
        """Parses expected_status_codes pattern and checks if status_code matches."""
        if not self.expected_status_codes:
            return 200 <= status_code < 300

        patterns = [p.strip() for p in self.expected_status_codes.split(',') if p.strip()]
        for pattern in patterns:
            if '-' in pattern:
                try:
                    start_str, end_str = pattern.split('-', 1)
                    start, end = int(start_str), int(end_str)
                    if start <= status_code <= end:
                        return True
                except ValueError:
                    continue
            else:
                try:
                    if int(pattern) == status_code:
                        return True
                except ValueError:
                    continue
        return False


class MonitorHeader(models.Model):
    monitor = models.ForeignKey(Monitor, on_delete=models.CASCADE, related_name='headers')
    name = models.CharField(max_length=120)
    value = models.TextField()
    is_secret = models.BooleanField(default=False, help_text="Mask header value in APIs and logs")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['id']
        unique_together = ('monitor', 'name')

    def __str__(self):
        masked = '********' if self.is_secret else self.value
        return f"{self.name}: {masked}"

    def safe_value(self) -> str:
        return '********' if self.is_secret else self.value
