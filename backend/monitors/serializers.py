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

    def validate_check_interval(self, value):
        if value < 10 or value > 86400:
            raise serializers.ValidationError("Check interval must be between 10 and 86400 seconds.")
        return value

    def validate_request_timeout(self, value):
        if value < 1 or value > 60:
            raise serializers.ValidationError("Request timeout must be between 1 and 60 seconds.")
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
            # Preserve existing secret header values if masked placeholder '********' is provided
            existing_headers = {h.name: h for h in instance.headers.all()}
            seen_names = set()

            for h in headers_data:
                name = h.get('name', '')
                val = h.get('value', '')
                is_sec = h.get('is_secret', False)
                if is_sec and (val == '********' or not val):
                    if name in existing_headers:
                        val = existing_headers[name].value

                if name in existing_headers:
                    existing_hdr = existing_headers[name]
                    existing_hdr.value = val
                    existing_hdr.is_secret = is_sec
                    existing_hdr.save()
                else:
                    MonitorHeader.objects.create(
                        monitor=instance,
                        name=name,
                        value=val,
                        is_secret=is_sec
                    )
                seen_names.add(name)

            # Remove headers deleted from the update payload
            for name, h_obj in existing_headers.items():
                if name not in seen_names:
                    h_obj.delete()

        return instance
