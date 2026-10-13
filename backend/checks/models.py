from django.db import models
from monitors.models import Monitor


class CheckResult(models.Model):
    OUTCOME_SUCCESS = 'success'
    OUTCOME_FAILURE = 'failure'
    OUTCOME_TIMEOUT = 'timeout'
    OUTCOME_ERROR = 'error'

    OUTCOME_CHOICES = [
        (OUTCOME_SUCCESS, 'Success'),
        (OUTCOME_FAILURE, 'Failure'),
        (OUTCOME_TIMEOUT, 'Timeout'),
        (OUTCOME_ERROR, 'Error'),
    ]

    monitor = models.ForeignKey(Monitor, on_delete=models.CASCADE, related_name='check_results', db_index=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    http_status_code = models.IntegerField(null=True, blank=True, help_text="HTTP status code returned, if any")
    response_time_ms = models.FloatField(help_text="Round-trip duration measured via monotonic clock in milliseconds")
    outcome = models.CharField(max_length=20, choices=OUTCOME_CHOICES, db_index=True)

    error_category = models.CharField(
        max_length=100,
        blank=True,
        default='',
        help_text="Standardized classification of check failure or error"
    )
    error_detail = models.TextField(
        blank=True,
        default='',
        help_text="Sanitized non-sensitive diagnostic message"
    )
    response_size_bytes = models.IntegerField(null=True, blank=True, help_text="Payload response size in bytes")

    expected_status_codes = models.CharField(max_length=100, help_text="Expected status configuration at time of check")
    status_matched = models.BooleanField(default=True, help_text="Whether actual status matched expected configuration")
    resolved_ip = models.CharField(max_length=45, blank=True, default='', help_text="Destination IP resolved for check")

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['monitor', '-created_at']),
            models.Index(fields=['monitor', 'outcome', '-created_at']),
            models.Index(fields=['-created_at']),
        ]

    def __str__(self):
        code_str = str(self.http_status_code) if self.http_status_code else "None"
        return f"[{self.outcome.upper()}] {self.monitor.name} - {code_str} ({self.response_time_ms:.1f}ms)"
