import pytest
from datetime import timedelta
from unittest.mock import patch
from django.utils import timezone
from django.core.cache import cache
from checks.models import CheckResult
from checks.tasks import dispatch_scheduled_checks, cleanup_old_records, execute_monitor_check_task


@pytest.mark.django_db
def test_dispatch_scheduled_checks_enqueues_due_monitors(monitor_factory, user1):
    now = timezone.now()
    # Due monitor: last checked 120s ago with 60s interval
    m1 = monitor_factory(owner=user1, check_interval=60)
    m1.last_checked_at = now - timedelta(seconds=120)
    m1.save()

    # Not due monitor: last checked 10s ago with 60s interval
    m2 = monitor_factory(owner=user1, name="Fresh Mon", check_interval=60)
    m2.last_checked_at = now - timedelta(seconds=10)
    m2.save()

    with patch('checks.tasks.execute_monitor_check_task.delay') as mock_delay:
        msg = dispatch_scheduled_checks()
        # Only m1 was due
        mock_delay.assert_called_once_with(m1.id)
        assert "Dispatched 1 monitor" in msg


@pytest.mark.django_db
def test_cleanup_old_records_purges_expired_data(monitor_factory, user1):
    mon = monitor_factory(owner=user1)
    now = timezone.now()

    # Create check older than 31 days
    old_check = CheckResult.objects.create(
        monitor=mon,
        response_time_ms=100.0,
        outcome='success',
        expected_status_codes='200'
    )
    old_check.created_at = now - timedelta(days=35)
    old_check.save()

    # Recent check from today
    new_check = CheckResult.objects.create(
        monitor=mon,
        response_time_ms=120.0,
        outcome='success',
        expected_status_codes='200'
    )

    assert CheckResult.objects.count() == 2

    # Run retention cleaner
    deleted = cleanup_old_records()
    assert deleted == 1
    assert CheckResult.objects.count() == 1
    assert CheckResult.objects.first().id == new_check.id


@pytest.mark.django_db
def test_execute_check_task_prevents_duplicate_runs(monitor_factory, user1):
    mon = monitor_factory(owner=user1)
    lock_key = f"monitor_check_lock_{mon.id}"

    # Simulate already locked monitor
    cache.set(lock_key, "locked", timeout=30)

    # Calling task while locked should return None and not run probe
    with patch('checks.tasks.execute_health_check') as mock_exec:
        result = execute_monitor_check_task(mon.id)
        assert result is None
        mock_exec.assert_not_called()

    # Clear lock
    cache.delete(lock_key)
