from rest_framework import serializers
from monitors.models import Monitor, MonitorHeader
from checks.ssrf import validate_url_syntax, SSRFSecurityError


class MonitorHeaderSerializer(serializers.ModelSerializer):
    class Meta:
        model = MonitorHeader
        fields = ['id', 'name', 'value', 'is_secret']

    def to_representation(self, instance):
        ret = super().to_representation(instance)
        if instance.is_secret:
            ret['value'] = '********'
        return ret


class MonitorSerializer(serializers.ModelSerializer):
    headers = MonitorHeaderSerializer(many=True, required=False)
    hostname = serializers.CharField(read_only=True)

    class Meta:
        model = Monitor
        fields = [
            'id', 'name', 'target_url', 'http_method', 'request_body', 'enabled',
            'check_interval', 'request_timeout', 'expected_status_codes',
            'latency_warning_threshold', 'latency_failure_threshold',
            'hostname', 'last_checked_at', 'last_status', 'last_response_time_ms',
            'last_status_code', 'consecutive_failures', 'headers',
            'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'hostname', 'last_checked_at', 'last_status',
            'last_response_time_ms', 'last_status_code', 'consecutive_failures',
            'created_at', 'updated_at'
        ]

    def validate_target_url(self, value):
        try:
            validate_url_syntax(value)
        except SSRFSecurityError as e:
            raise serializers.ValidationError(str(e))
        return value

    def validate(self, attrs):
        warn = attrs.get('latency_warning_threshold', getattr(self.instance, 'latency_warning_threshold', 500))
        fail = attrs.get('latency_failure_threshold', getattr(self.instance, 'latency_failure_threshold', 2000))
        if fail < warn:
            raise serializers.ValidationError({
                'latency_failure_threshold': 'Critical failure threshold cannot be less than warning threshold.'
            })
        return attrs

    def create(self, validated_data):
        headers_data = validated_data.pop('headers', [])
        monitor = Monitor.objects.create(**validated_data)
        for h in headers_data:
            MonitorHeader.objects.create(monitor=monitor, **h)
        return monitor

    def update(self, instance, validated_data):
        headers_data = validated_data.pop('headers', None)
        for attr, val in validated_data.items():
            setattr(instance, attr, val)
        instance.save()

        if headers_data is not None:
            instance.headers.all().delete()
            for h in headers_data:
                MonitorHeader.objects.create(monitor=instance, **h)

        return instance
