from django.urls import path
from .views import (
    WebChecksHistoryView,
    CheckResultListAPIView,
    CheckResultDetailAPIView
)

urlpatterns = [
    # Web UI
    path('checks/', WebChecksHistoryView.as_view(), name='checks_history'),

    # REST API
    path('api/v1/checks/', CheckResultListAPIView.as_view(), name='api-checks-list'),
    path('api/v1/checks/<int:pk>/', CheckResultDetailAPIView.as_view(), name='api-checks-detail'),
]
