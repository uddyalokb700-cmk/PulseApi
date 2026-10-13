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

    def validate(self, attrs):
        channel = attrs.get('channel', getattr(self.instance, 'channel', None))
        target = attrs.get('target', getattr(self.instance, 'target', None))

        if channel == NotificationConfig.CHANNEL_WEBHOOK and target:
            from checks.ssrf import validate_url_syntax, SSRFSecurityError
            try:
                validate_url_syntax(target)
            except SSRFSecurityError as e:
                raise serializers.ValidationError({'target': str(e)})
        elif channel == NotificationConfig.CHANNEL_EMAIL and target:
            from django.core.validators import validate_email
            from django.core.exceptions import ValidationError
            try:
                validate_email(target)
            except ValidationError:
                raise serializers.ValidationError({'target': 'Enter a valid email address.'})

        return attrs
