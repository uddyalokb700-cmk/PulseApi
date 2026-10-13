from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from django.views import View
from django.contrib import messages
from django.utils import timezone
from rest_framework import generics, permissions, status
from rest_framework.views import APIView
from rest_framework.response import Response
from drf_spectacular.utils import extend_schema
from alerts.models import AlertEvent, NotificationConfig
from alerts.serializers import AlertEventSerializer, NotificationConfigSerializer


# --- REST API Endpoints ---

class AlertEventListAPIView(generics.ListAPIView):
    serializer_class = AlertEventSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        qs = AlertEvent.objects.filter(monitor__owner=self.request.user).select_related('monitor')
        state = self.request.query_params.get('state')
        severity = self.request.query_params.get('severity')
        monitor_id = self.request.query_params.get('monitor')

        if state:
            qs = qs.filter(state=state.lower())
        if severity:
            qs = qs.filter(severity=severity.lower())
        if monitor_id:
            qs = qs.filter(monitor_id=monitor_id)

        return qs.order_by('-triggered_at')


class AlertEventResolveAPIView(APIView):
    serializer_class = AlertEventSerializer
    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(
        request=None,
        summary="Acknowledge and resolve an active alert event",
        responses={200: AlertEventSerializer}
    )
    def post(self, request, pk):
        alert = get_object_or_404(AlertEvent, pk=pk, monitor__owner=request.user)
        alert.state = AlertEvent.STATE_RESOLVED
        alert.resolved_at = timezone.now()
        alert.save(update_fields=['state', 'resolved_at'])
        return Response(AlertEventSerializer(alert).data, status=status.HTTP_200_OK)


class NotificationConfigListCreateAPIView(generics.ListCreateAPIView):
    serializer_class = NotificationConfigSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return NotificationConfig.objects.filter(owner=self.request.user)

    def perform_create(self, serializer):
        serializer.save(owner=self.request.user)


class NotificationConfigDetailAPIView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = NotificationConfigSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return NotificationConfig.objects.filter(owner=self.request.user)


# --- Browser Web Views ---

@method_decorator(login_required, name='dispatch')
class WebAlertsView(View):
    def get(self, request):
        state_filter = request.GET.get('state', '').lower()
        qs = AlertEvent.objects.filter(monitor__owner=request.user).select_related('monitor')

        if state_filter in ('active', 'resolved'):
            qs = qs.filter(state=state_filter)

        alerts = qs.order_by('-triggered_at')[:50]
        active_count = AlertEvent.objects.filter(monitor__owner=request.user, state='active').count()

        return render(request, 'dashboard/alerts.html', {
            'alerts': alerts,
            'active_count': active_count,
            'current_state': state_filter,
        })


@method_decorator(login_required, name='dispatch')
class WebAlertResolveActionView(View):
    def post(self, request, pk):
        alert = get_object_or_404(AlertEvent, pk=pk, monitor__owner=request.user)
        alert.state = AlertEvent.STATE_RESOLVED
        alert.resolved_at = timezone.now()
        alert.save(update_fields=['state', 'resolved_at'])
        messages.success(request, f"Alert for '{alert.monitor.name}' marked as resolved.")
        return redirect('alerts_list')


@method_decorator(login_required, name='dispatch')
class WebSettingsView(View):
    def get(self, request):
        configs = NotificationConfig.objects.filter(owner=request.user)
        return render(request, 'dashboard/settings.html', {'configs': configs})

    def post(self, request):
        channel = request.POST.get('channel', 'email')
        target = request.POST.get('target', '').strip()
        secret_token = request.POST.get('secret_token', '').strip()
        notify_fail = 'notify_on_failure' in request.POST
        notify_lat = 'notify_on_latency' in request.POST
        notify_rec = 'notify_on_recovery' in request.POST

        if not target:
            messages.error(request, "Target recipient address or URL cannot be empty.")
            return redirect('settings_view')

        if channel == NotificationConfig.CHANNEL_WEBHOOK:
            from checks.ssrf import validate_url_syntax, SSRFSecurityError
            try:
                validate_url_syntax(target)
            except SSRFSecurityError as e:
                messages.error(request, f"Invalid or unsafe webhook URL: {e}")
                return redirect('settings_view')
        elif channel == NotificationConfig.CHANNEL_EMAIL:
            from django.core.validators import validate_email
            from django.core.exceptions import ValidationError
            try:
                validate_email(target)
            except ValidationError:
                messages.error(request, "Invalid recipient email address.")
                return redirect('settings_view')

        NotificationConfig.objects.create(
            owner=request.user,
            channel=channel,
            target=target,
            secret_token=secret_token,
            notify_on_failure=notify_fail,
            notify_on_latency=notify_lat,
            notify_on_recovery=notify_rec,
            enabled=True
        )
        messages.success(request, f"Notification channel ({channel.capitalize()}) registered successfully.")
        return redirect('settings_view')


@method_decorator(login_required, name='dispatch')
class WebNotificationDeleteView(View):
    def post(self, request, pk):
        cfg = get_object_or_404(NotificationConfig, pk=pk, owner=request.user)
        cfg.delete()
        messages.success(request, "Notification config deleted.")
        return redirect('settings_view')
