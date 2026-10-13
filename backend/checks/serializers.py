from rest_framework import serializers
from checks.models import CheckResult


class CheckResultSerializer(serializers.ModelSerializer):
    monitor_name = serializers.CharField(source='monitor.name', read_only=True)
    monitor_target_url = serializers.CharField(source='monitor.target_url', read_only=True)

    class Meta:
        model = CheckResult
        fields = [
            'id', 'monitor', 'monitor_name', 'monitor_target_url',
            'created_at', 'http_status_code', 'response_time_ms',
            'outcome', 'error_category', 'error_detail',
            'response_size_bytes', 'expected_status_codes',
            'status_matched', 'resolved_ip'
        ]
        read_only_fields = fields
