from datetime import timedelta
import logging
from celery import shared_task
from django.utils import timezone
from django.conf import settings
from django.core.cache import cache
from monitors.models import Monitor
from checks.models import CheckResult
from checks.engine import execute_health_check

logger = logging.getLogger('pulseapi.checks')


@shared_task(bind=True, max_retries=1, default_retry_delay=5)
def execute_monitor_check_task(self, monitor_id: int):
    """
    Celery task to execute a health check for a single monitor.
    Uses distributed cache lock to prevent concurrent redundant execution.
    """
    lock_key = f"monitor_check_lock_{monitor_id}"
    # Acquire non-blocking lock with 30s TTL
    acquired = cache.add(lock_key, "locked", timeout=30)
    if not acquired:
        logger.info(f"Check for monitor {monitor_id} is already in progress. Skipping duplicate dispatch.")
        return None

    try:
        try:
            monitor = Monitor.objects.get(id=monitor_id, enabled=True)
        except Monitor.DoesNotExist:
            logger.info(f"Monitor {monitor_id} no longer exists or is disabled.")
            return None

        result = execute_health_check(monitor)
        return {
            'monitor_id': monitor.id,
            'outcome': result.outcome,
            'status_code': result.http_status_code,
            'duration_ms': result.response_time_ms
        }
    except Exception as exc:
        logger.exception(f"Unexpected error running check for monitor {monitor_id}: {exc}")
        raise
    finally:
        cache.delete(lock_key)


@shared_task
def dispatch_scheduled_checks():
    """
    Periodic beat task: scans all enabled monitors and enqueues check tasks
    if their scheduled interval has elapsed.
    """
    now = timezone.now()
    enabled_monitors = Monitor.objects.filter(enabled=True)
    dispatched_count = 0

    for monitor in enabled_monitors:
        # Check if due
        if monitor.last_checked_at is None:
            is_due = True
        else:
            elapsed = (now - monitor.last_checked_at).total_seconds()
            is_due = elapsed >= monitor.check_interval

        if is_due:
            execute_monitor_check_task.delay(monitor.id)
            dispatched_count += 1

    return f"Dispatched {dispatched_count} monitor health checks at {now.isoformat()}"


@shared_task
def cleanup_old_records():
    """
    Periodic retention maintenance: removes CheckResult entries older than
    CHECK_RETENTION_DAYS to maintain optimal query performance and bounded storage.
    """
    retention_days = getattr(settings, 'CHECK_RETENTION_DAYS', 30)
    cutoff = timezone.now() - timedelta(days=retention_days)
    deleted_count, _ = CheckResult.objects.filter(created_at__lt=cutoff).delete()
    logger.info(f"Pruned {deleted_count} expired CheckResult records older than {cutoff.isoformat()}.")
    return deleted_count
