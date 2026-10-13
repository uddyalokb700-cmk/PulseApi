from django.contrib import admin
from .models import Monitor, MonitorHeader


class MonitorHeaderInline(admin.TabularInline):
    model = MonitorHeader
    extra = 0
    readonly_fields = ['masked_value']
    fields = ['name', 'is_secret', 'masked_value']

    def masked_value(self, obj):
        if obj and obj.is_secret:
            return '********'
        return obj.value if obj else ''


@admin.register(Monitor)
class MonitorAdmin(admin.ModelAdmin):
    list_display = ['name', 'target_url', 'owner', 'last_status', 'enabled', 'last_checked_at']
    list_filter = ['last_status', 'enabled', 'http_method']
    search_fields = ['name', 'target_url', 'owner__username']
    inlines = [MonitorHeaderInline]


@admin.register(MonitorHeader)
class MonitorHeaderAdmin(admin.ModelAdmin):
    list_display = ['name', 'monitor', 'is_secret', 'masked_value']
    list_filter = ['is_secret']
    search_fields = ['name', 'monitor__name']

    def masked_value(self, obj):
        if obj.is_secret:
            return '********'
        return obj.value
