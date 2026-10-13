from django.contrib import admin
from .models import CheckResult


@admin.register(CheckResult)
class CheckResultAdmin(admin.ModelAdmin):
    list_display = ['monitor', 'outcome', 'http_status_code', 'response_time_ms', 'created_at']
    list_filter = ['outcome', 'http_status_code']
    search_fields = ['monitor__name', 'resolved_ip']
    readonly_fields = [
        'monitor', 'http_status_code', 'response_time_ms', 'outcome',
        'error_category', 'error_detail', 'response_size_bytes',
        'expected_status_codes', 'status_matched', 'resolved_ip', 'created_at'
    ]
