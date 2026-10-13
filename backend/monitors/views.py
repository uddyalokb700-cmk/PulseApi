from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from django.views import View
from django.contrib import messages
from django.http import Http404
from rest_framework import generics, permissions, status
from rest_framework.views import APIView
from rest_framework.response import Response
from drf_spectacular.utils import extend_schema
from monitors.models import Monitor, MonitorHeader
from monitors.serializers import MonitorSerializer
from checks.engine import execute_health_check
from checks.models import CheckResult


# --- REST API Endpoints ---

class MonitorListCreateAPIView(generics.ListCreateAPIView):
    serializer_class = MonitorSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        qs = Monitor.objects.filter(owner=self.request.user)
        status_filter = self.request.query_params.get('status')
        search_query = self.request.query_params.get('q')

        if status_filter:
            qs = qs.filter(last_status=status_filter.lower())
        if search_query:
            qs = qs.filter(name__icontains=search_query) | qs.filter(target_url__icontains=search_query)

        return qs.order_by('-created_at')

    def perform_create(self, serializer):
        serializer.save(owner=self.request.user)


class MonitorDetailAPIView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = MonitorSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        # Strict object-level ownership scope
        return Monitor.objects.filter(owner=self.request.user)


class MonitorToggleAPIView(APIView):
    serializer_class = MonitorSerializer
    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(
        request=None,
        responses={200: MonitorSerializer},
        summary="Toggle monitor enabled/disabled status"
    )
    def post(self, request, pk):
        try:
            monitor = Monitor.objects.get(pk=pk, owner=request.user)
        except Monitor.DoesNotExist:
            raise Http404("Monitor not found or unauthorized.")

        monitor.enabled = not monitor.enabled
        monitor.save(update_fields=['enabled', 'updated_at'])
        return Response(MonitorSerializer(monitor).data, status=status.HTTP_200_OK)


class MonitorManualCheckAPIView(APIView):
    serializer_class = None
    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(
        request=None,
        summary="Trigger immediate authorized manual health check",
        description="Executes a synchronous, bounded health check on the specified monitor and updates its telemetry."
    )
    def post(self, request, pk):
        try:
            monitor = Monitor.objects.get(pk=pk, owner=request.user)
        except Monitor.DoesNotExist:
            raise Http404("Monitor not found or unauthorized.")

        # Rate-limit manual probes to prevent worker capacity exhaustion / DoS
        from django.core.cache import cache
        lock_key = f"manual_probe_lock_{monitor.id}"
        if not cache.add(lock_key, "locked", timeout=5):
            return Response(
                {"detail": "Manual health check in progress or cooldown active. Please wait 5 seconds before retrying."},
                status=status.HTTP_429_TOO_MANY_REQUESTS
            )

        check_result = execute_health_check(monitor, is_manual=True)

        return Response({
            "message": "Manual check completed",
            "monitor_id": monitor.id,
            "monitor_name": monitor.name,
            "outcome": check_result.outcome,
            "http_status_code": check_result.http_status_code,
            "response_time_ms": check_result.response_time_ms,
            "status_matched": check_result.status_matched,
            "error_category": check_result.error_category,
            "error_detail": check_result.error_detail,
            "checked_at": check_result.created_at.isoformat(),
            "latest_status": monitor.last_status,
        }, status=status.HTTP_200_OK)


# --- Browser Web Views ---

@method_decorator(login_required, name='dispatch')
class WebOverviewView(View):
    def get(self, request):
        monitors = Monitor.objects.filter(owner=request.user)
        total = monitors.count()
        enabled = monitors.filter(enabled=True).count()
        healthy = monitors.filter(last_status=Monitor.STATUS_HEALTHY).count()
        degraded = monitors.filter(last_status=Monitor.STATUS_DEGRADED).count()
        failing = monitors.filter(last_status=Monitor.STATUS_FAILING).count()

        # Recent 5 checks across all monitors
        recent_checks = CheckResult.objects.filter(monitor__owner=request.user).select_related('monitor')[:8]

        # Recent 5 alerts
        from alerts.models import AlertEvent
        recent_alerts = AlertEvent.objects.filter(monitor__owner=request.user).select_related('monitor')[:6]

        context = {
            'total_monitors': total,
            'enabled_monitors': enabled,
            'healthy_monitors': healthy,
            'degraded_monitors': degraded,
            'failing_monitors': failing,
            'recent_checks': recent_checks,
            'recent_alerts': recent_alerts,
            'monitors': monitors[:10],
        }
        return render(request, 'dashboard/overview.html', context)


@method_decorator(login_required, name='dispatch')
class WebMonitorsListView(View):
    def get(self, request):
        status_filter = request.GET.get('status', '').strip().lower()
        search_query = request.GET.get('q', '').strip()

        qs = Monitor.objects.filter(owner=request.user)
        if status_filter in ('healthy', 'degraded', 'failing', 'pending'):
            qs = qs.filter(last_status=status_filter)
        elif status_filter == 'disabled':
            qs = qs.filter(enabled=False)

        if search_query:
            qs = qs.filter(name__icontains=search_query) | qs.filter(target_url__icontains=search_query)

        return render(request, 'dashboard/monitors.html', {
            'monitors': qs,
            'current_status': status_filter,
            'search_query': search_query,
        })


@method_decorator(login_required, name='dispatch')
class WebMonitorCreateView(View):
    def get(self, request):
        return render(request, 'dashboard/monitor_create.html')

    def post(self, request):
        name = request.POST.get('name', '').strip()
        target_url = request.POST.get('target_url', '').strip()
        http_method = request.POST.get('http_method', 'GET').upper()

        try:
            check_interval = int(request.POST.get('check_interval', 60))
            request_timeout = int(request.POST.get('request_timeout', 10))
            latency_warning = int(request.POST.get('latency_warning_threshold', 500))
            latency_failure = int(request.POST.get('latency_failure_threshold', 2000))
        except (ValueError, TypeError):
            messages.error(request, "Invalid numeric input provided for intervals or thresholds.")
            return render(request, 'dashboard/monitor_create.html', {'post': request.POST})

        expected_status_codes = request.POST.get('expected_status_codes', '200-299').strip()
        request_body = request.POST.get('request_body', '').strip()

        if check_interval < 10 or check_interval > 86400:
            messages.error(request, "Check interval must be between 10 and 86400 seconds.")
            return render(request, 'dashboard/monitor_create.html', {'post': request.POST})

        if request_timeout < 1 or request_timeout > 60:
            messages.error(request, "Request timeout must be between 1 and 60 seconds.")
            return render(request, 'dashboard/monitor_create.html', {'post': request.POST})

        try:
            from checks.ssrf import validate_url_syntax
            validate_url_syntax(target_url)
        except Exception as e:
            messages.error(request, f"Invalid target URL: {e}")
            return render(request, 'dashboard/monitor_create.html', {'post': request.POST})

        if latency_failure < latency_warning:
            messages.error(request, "Critical latency threshold cannot be lower than warning threshold.")
            return render(request, 'dashboard/monitor_create.html', {'post': request.POST})

        monitor = Monitor.objects.create(
            owner=request.user,
            name=name,
            target_url=target_url,
            http_method=http_method,
            check_interval=check_interval,
            request_timeout=request_timeout,
            expected_status_codes=expected_status_codes,
            latency_warning_threshold=latency_warning,
            latency_failure_threshold=latency_failure,
            request_body=request_body,
            enabled=True
        )

        # Process optional custom headers
        header_names = request.POST.getlist('header_name[]')
        header_values = request.POST.getlist('header_value[]')
        header_secrets = request.POST.getlist('header_secret[]')

        for i, h_name in enumerate(header_names):
            h_name = h_name.strip()
            if h_name and i < len(header_values):
                val = header_values[i]
                is_sec = str(i) in header_secrets or f"secret_{i}" in header_secrets
                MonitorHeader.objects.create(
                    monitor=monitor,
                    name=h_name,
                    value=val,
                    is_secret=is_sec
                )

        messages.success(request, f"Monitor '{monitor.name}' registered successfully! Testing endpoint now...")
        # Run initial immediate check
        execute_health_check(monitor, is_manual=True)

        return redirect('monitor_detail', pk=monitor.pk)


@method_decorator(login_required, name='dispatch')
class WebMonitorDetailView(View):
    def get(self, request, pk):
        monitor = get_object_or_404(Monitor, pk=pk, owner=request.user)
        checks = monitor.check_results.all()[:30]
        alerts = monitor.alerts.all()[:15]
        return render(request, 'dashboard/monitor_detail.html', {
            'monitor': monitor,
            'checks': checks,
            'alerts': alerts,
        })


@method_decorator(login_required, name='dispatch')
class WebMonitorDeleteView(View):
    def post(self, request, pk):
        monitor = get_object_or_404(Monitor, pk=pk, owner=request.user)
        name = monitor.name
        monitor.delete()
        messages.success(request, f"Monitor '{name}' has been deleted.")
        return redirect('monitors_list')
