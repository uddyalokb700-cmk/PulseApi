from rest_framework import serializers
from alerts.models import AlertEvent, NotificationConfig


class AlertEventSerializer(serializers.ModelSerializer):
    monitor_name = serializers.CharField(source='monitor.name', read_only=True)

    class Meta:
        model = AlertEvent
        fields = [
            'id', 'monitor', 'monitor_name', 'alert_type', 'severity',
            'state', 'triggered_at', 'resolved_at', 'description', 'consecutive_count'
        ]
        read_only_fields = fields


class NotificationConfigSerializer(serializers.ModelSerializer):
    class Meta:
        model = NotificationConfig
        fields = [
            'id', 'channel', 'enabled', 'target', 'secret_token',
            'notify_on_failure', 'notify_on_latency', 'notify_on_recovery',
            'created_at', 'updated_at'
        ]
        extra_kwargs = {
            'secret_token': {'write_only': True}
        }
