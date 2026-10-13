from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import permissions, status
from drf_spectacular.utils import extend_schema, OpenApiParameter
from analytics.services import (
    calculate_performance_summary,
    calculate_timeseries_latency,
    calculate_status_distribution,
    calculate_endpoint_comparison
)


class PerformanceSummaryAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(
        parameters=[
            OpenApiParameter('monitor', int, required=False, description="Filter by specific monitor ID"),
            OpenApiParameter('range', str, required=False, description="Time window: 1h, 24h, 7d, 30d"),
        ],
        summary="Retrieve aggregated performance summary metrics"
    )
    def get(self, request):
        monitor_id = request.query_params.get('monitor')
        time_range = request.query_params.get('range', '24h')
        summary = calculate_performance_summary(request.user, monitor_id=monitor_id, time_range=time_range)
        return Response(summary)


class TimeseriesLatencyAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(
        parameters=[
            OpenApiParameter('monitor', int, required=False, description="Filter by specific monitor ID"),
            OpenApiParameter('range', str, required=False, description="Time window: 1h, 24h, 7d, 30d"),
        ],
        summary="Retrieve latency timeseries data points"
    )
    def get(self, request):
        monitor_id = request.query_params.get('monitor')
        time_range = request.query_params.get('range', '24h')
        points = calculate_timeseries_latency(request.user, monitor_id=monitor_id, time_range=time_range)
        return Response({'points': points})


class StatusDistributionAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(
        parameters=[
            OpenApiParameter('monitor', int, required=False, description="Filter by specific monitor ID"),
            OpenApiParameter('range', str, required=False, description="Time window: 1h, 24h, 7d, 30d"),
        ],
        summary="Retrieve HTTP status code and error breakdown"
    )
    def get(self, request):
        monitor_id = request.query_params.get('monitor')
        time_range = request.query_params.get('range', '24h')
        dist = calculate_status_distribution(request.user, monitor_id=monitor_id, time_range=time_range)
        return Response(dist)


class EndpointComparisonAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(
        parameters=[
            OpenApiParameter('range', str, required=False, description="Time window: 1h, 24h, 7d, 30d"),
        ],
        summary="Retrieve comparative latency and availability metrics across endpoints"
    )
    def get(self, request):
        time_range = request.query_params.get('range', '24h')
        comparison = calculate_endpoint_comparison(request.user, time_range=time_range)
        return Response({'endpoints': comparison})


class SystemHealthAPIView(APIView):
    permission_classes = [permissions.AllowAny]

    @extend_schema(
        summary="Internal system health check",
        description="Verifies PulseAPI web service and database connectivity"
    )
    def get(self, request):
        from django.db import connection
        db_healthy = True
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
        except Exception:
            db_healthy = False

        status_code = status.HTTP_200_OK if db_healthy else status.HTTP_503_SERVICE_UNAVAILABLE
        return Response({
            "status": "healthy" if db_healthy else "unhealthy",
            "database": "connected" if db_healthy else "disconnected",
            "service": "PulseAPI Observability Engine",
            "version": "1.0.0"
        }, status=status_code)
