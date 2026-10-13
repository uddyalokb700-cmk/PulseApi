from django.urls import path
from .views import (
    WebAlertsView, WebAlertResolveActionView,
    WebSettingsView, WebNotificationDeleteView,
    AlertEventListAPIView, AlertEventResolveAPIView,
    NotificationConfigListCreateAPIView, NotificationConfigDetailAPIView
)

urlpatterns = [
    # Web UI
    path('alerts/', WebAlertsView.as_view(), name='alerts_list'),
    path('alerts/<int:pk>/resolve/', WebAlertResolveActionView.as_view(), name='alert_resolve_web'),
    path('settings/', WebSettingsView.as_view(), name='settings_view'),
    path('settings/notifications/<int:pk>/delete/', WebNotificationDeleteView.as_view(), name='notification_delete_web'),

    # REST API
    path('api/v1/alerts/', AlertEventListAPIView.as_view(), name='api-alerts-list'),
    path('api/v1/alerts/<int:pk>/resolve/', AlertEventResolveAPIView.as_view(), name='api-alerts-resolve'),
    path('api/v1/notifications/', NotificationConfigListCreateAPIView.as_view(), name='api-notifications-list-create'),
    path('api/v1/notifications/<int:pk>/', NotificationConfigDetailAPIView.as_view(), name='api-notifications-detail'),
]
