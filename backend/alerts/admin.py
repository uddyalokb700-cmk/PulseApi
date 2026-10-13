from django.contrib import admin
from .models import AlertEvent, NotificationConfig


@admin.register(AlertEvent)
class AlertEventAdmin(admin.ModelAdmin):
    list_display = ['monitor', 'alert_type', 'severity', 'state', 'triggered_at', 'resolved_at']
    list_filter = ['state', 'severity', 'alert_type']
    search_fields = ['monitor__name', 'description']


@admin.register(NotificationConfig)
class NotificationConfigAdmin(admin.ModelAdmin):
    list_display = ['owner', 'channel', 'target', 'enabled', 'masked_token']
    list_filter = ['channel', 'enabled']
    search_fields = ['owner__username', 'target']
    readonly_fields = ['masked_token']

    def masked_token(self, obj):
        if obj and obj.secret_token:
            return '********'
        return ''
