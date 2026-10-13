from django.urls import path
from .views import (
    WebOverviewView, WebMonitorsListView, WebMonitorCreateView,
    WebMonitorDetailView, WebMonitorDeleteView,
    MonitorListCreateAPIView, MonitorDetailAPIView,
    MonitorToggleAPIView, MonitorManualCheckAPIView
)

urlpatterns = [
    # Web UI
    path('', WebOverviewView.as_view(), name='overview'),
    path('monitors/', WebMonitorsListView.as_view(), name='monitors_list'),
    path('monitors/create/', WebMonitorCreateView.as_view(), name='monitor_create'),
    path('monitors/<int:pk>/', WebMonitorDetailView.as_view(), name='monitor_detail'),
    path('monitors/<int:pk>/delete/', WebMonitorDeleteView.as_view(), name='monitor_delete'),

    # REST API
    path('api/v1/monitors/', MonitorListCreateAPIView.as_view(), name='api-monitors-list-create'),
    path('api/v1/monitors/<int:pk>/', MonitorDetailAPIView.as_view(), name='api-monitors-detail'),
    path('api/v1/monitors/<int:pk>/toggle/', MonitorToggleAPIView.as_view(), name='api-monitors-toggle'),
    path('api/v1/monitors/<int:pk>/check-now/', MonitorManualCheckAPIView.as_view(), name='api-monitors-check-now'),
]
