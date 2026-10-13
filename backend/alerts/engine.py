from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
import logging
from .models import AlertEvent, NotificationConfig

logger = logging.getLogger('pulseapi.alerts')


def evaluate_monitor_alerts(monitor, check_result):
    """
    Evaluates check results against alert policies with deduplication,
    state transition handling, and recovery detection.
    """
    now = timezone.now()
    active_alerts = AlertEvent.objects.filter(monitor=monitor, state=AlertEvent.STATE_ACTIVE)

    # 1. Recovery condition: check succeeded and latency is below warning threshold
    is_healthy_now = (
        check_result.outcome == 'success' and
        check_result.response_time_ms <= monitor.latency_warning_threshold
    )

    if is_healthy_now:
        if active_alerts.exists():
            # Resolve all previously active failure or latency alerts
            for alert in active_alerts:
                alert.state = AlertEvent.STATE_RESOLVED
                alert.resolved_at = now
                alert.save(update_fields=['state', 'resolved_at'])

            # Log recovery event
            recovery_alert = AlertEvent.objects.create(
                monitor=monitor,
                alert_type=AlertEvent.TYPE_RECOVERY,
                severity=AlertEvent.SEVERITY_INFO,
                state=AlertEvent.STATE_RESOLVED,
                resolved_at=now,
                description=(
                    f"Monitor '{monitor.name}' has recovered. Endpoint responded with "
                    f"HTTP {check_result.http_status_code} in {check_result.response_time_ms:.1f}ms."
                )
            )
            dispatch_notifications(monitor, recovery_alert)
        return

    # 2. Complete check failure (timeout, error, status mismatch)
    if check_result.outcome in ('failure', 'timeout', 'error'):
        if monitor.consecutive_failures >= 3:
            alert_type = AlertEvent.TYPE_REPEATED_FAILURE
            severity = AlertEvent.SEVERITY_CRITICAL
            desc = (
                f"Critical: Monitor '{monitor.name}' has failed {monitor.consecutive_failures} consecutive checks. "
                f"Latest error: {check_result.error_category} ({check_result.error_detail})."
            )
        else:
            alert_type = AlertEvent.TYPE_ENDPOINT_DOWN
            severity = AlertEvent.SEVERITY_WARNING if monitor.consecutive_failures == 1 else AlertEvent.SEVERITY_CRITICAL
            desc = (
                f"Failure detected for '{monitor.name}': outcome '{check_result.outcome}', "
                f"HTTP {check_result.http_status_code or 'N/A'}. Reason: {check_result.error_category or 'Check failed'}."
            )

        # Deduplicate: check if an active alert of this type or endpoint_down already exists
        existing_active = active_alerts.filter(
            alert_type__in=[AlertEvent.TYPE_ENDPOINT_DOWN, AlertEvent.TYPE_REPEATED_FAILURE]
        ).first()

        if existing_active:
            # Increment consecutive counter without creating duplicate event
            existing_active.consecutive_count = monitor.consecutive_failures
            existing_active.description = desc
            if severity == AlertEvent.SEVERITY_CRITICAL and existing_active.severity != AlertEvent.SEVERITY_CRITICAL:
                existing_active.severity = AlertEvent.SEVERITY_CRITICAL
                existing_active.alert_type = alert_type
            existing_active.save(update_fields=['consecutive_count', 'description', 'severity', 'alert_type'])
        else:
            alert = AlertEvent.objects.create(
                monitor=monitor,
                alert_type=alert_type,
                severity=severity,
                state=AlertEvent.STATE_ACTIVE,
                description=desc,
                consecutive_count=monitor.consecutive_failures
            )
            dispatch_notifications(monitor, alert)
        return

    # 3. Latency threshold alerts for successful HTTP responses
    if check_result.outcome == 'success':
        duration = check_result.response_time_ms
        if duration >= monitor.latency_failure_threshold:
            alert_type = AlertEvent.TYPE_LATENCY_FAILURE
            severity = AlertEvent.SEVERITY_CRITICAL
            desc = (
                f"Critical latency violation for '{monitor.name}': response duration {duration:.1f}ms "
                f"exceeded critical ceiling of {monitor.latency_failure_threshold}ms."
            )
        elif duration >= monitor.latency_warning_threshold:
            alert_type = AlertEvent.TYPE_LATENCY_WARNING
            severity = AlertEvent.SEVERITY_WARNING
            desc = (
                f"Latency warning for '{monitor.name}': response duration {duration:.1f}ms "
                f"exceeded warning threshold of {monitor.latency_warning_threshold}ms."
            )
        else:
            alert_type = None

        if alert_type:
            existing_latency_alert = active_alerts.filter(
                alert_type__in=[AlertEvent.TYPE_LATENCY_WARNING, AlertEvent.TYPE_LATENCY_FAILURE]
            ).first()

            if existing_latency_alert:
                existing_latency_alert.description = desc
                existing_latency_alert.severity = severity
                existing_latency_alert.alert_type = alert_type
                existing_latency_alert.save(update_fields=['description', 'severity', 'alert_type'])
            else:
                alert = AlertEvent.objects.create(
                    monitor=monitor,
                    alert_type=alert_type,
                    severity=severity,
                    state=AlertEvent.STATE_ACTIVE,
                    description=desc,
                    consecutive_count=1
                )
                dispatch_notifications(monitor, alert)


def dispatch_notifications(monitor, alert_event):
    """
    Sends alerts to configured notification channels (Email, Webhook).
    """
    configs = NotificationConfig.objects.filter(owner=monitor.owner, enabled=True)
    if not configs.exists():
        return

    for config in configs:
        if alert_event.alert_type == AlertEvent.TYPE_RECOVERY and not config.notify_on_recovery:
            continue
        if 'latency' in alert_event.alert_type and not config.notify_on_latency:
            continue
        if alert_event.alert_type in (AlertEvent.TYPE_ENDPOINT_DOWN, AlertEvent.TYPE_REPEATED_FAILURE) and not config.notify_on_failure:
            continue

        if config.channel == NotificationConfig.CHANNEL_EMAIL:
            try:
                subject = f"[PulseAPI {alert_event.severity.upper()}] {monitor.name}: {alert_event.get_alert_type_display()}"
                message = f"{alert_event.description}\n\nTimestamp: {alert_event.triggered_at.isoformat()}\nTarget URL: {monitor.target_url}"
                send_mail(
                    subject=subject,
                    message=message,
                    from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', 'alerts@pulseapi.dev'),
                    recipient_list=[config.target],
                    fail_silently=True
                )
            except Exception as e:
                logger.warning(f"Failed to dispatch email alert to {config.target}: {e}")

        elif config.channel == NotificationConfig.CHANNEL_WEBHOOK:
            # In a production environment, webhooks would be posted securely via an async task
            logger.info(f"Triggering webhook notification to {config.target} for alert {alert_event.id}")
