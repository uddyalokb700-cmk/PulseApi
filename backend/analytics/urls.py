from django.urls import path
from .views import (
    PerformanceSummaryAPIView,
    TimeseriesLatencyAPIView,
    StatusDistributionAPIView,
    EndpointComparisonAPIView,
    SystemHealthAPIView
)

urlpatterns = [
    path('api/v1/analytics/summary/', PerformanceSummaryAPIView.as_view(), name='api-analytics-summary'),
    path('api/v1/analytics/timeseries/', TimeseriesLatencyAPIView.as_view(), name='api-analytics-timeseries'),
    path('api/v1/analytics/status-distribution/', StatusDistributionAPIView.as_view(), name='api-analytics-status-distribution'),
    path('api/v1/analytics/comparison/', EndpointComparisonAPIView.as_view(), name='api-analytics-comparison'),
    path('api/v1/health/', SystemHealthAPIView.as_view(), name='api-system-health'),
]
