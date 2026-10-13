import pytest
from rest_framework import status
from checks.models import CheckResult
from alerts.models import AlertEvent
from alerts.engine import evaluate_monitor_alerts


@pytest.mark.django_db
def test_failure_alert_creation_and_deduplication(monitor_factory, user1):
    mon = monitor_factory(owner=user1, latency_warning_threshold=500, latency_failure_threshold=2000)

    # 1. First failure check
    fail1 = CheckResult.objects.create(
        monitor=mon,
        http_status_code=500,
        response_time_ms=120.0,
        outcome='failure',
        error_category='status_mismatch',
        error_detail='HTTP 500 received',
        expected_status_codes='200',
        status_matched=False
    )
    mon.consecutive_failures = 1
    evaluate_monitor_alerts(mon, fail1)

    assert AlertEvent.objects.filter(monitor=mon, state='active').count() == 1
    alert = AlertEvent.objects.filter(monitor=mon, state='active').first()
    assert alert.alert_type == AlertEvent.TYPE_ENDPOINT_DOWN
    assert alert.consecutive_count == 1

    # 2. Second failure check should DEDUPLICATE (not create a new alert, but update count)
    fail2 = CheckResult.objects.create(
        monitor=mon,
        http_status_code=500,
        response_time_ms=130.0,
        outcome='failure',
        error_category='status_mismatch',
        expected_status_codes='200',
        status_matched=False
    )
    mon.consecutive_failures = 2
    evaluate_monitor_alerts(mon, fail2)

    assert AlertEvent.objects.filter(monitor=mon, state='active').count() == 1
    alert.refresh_from_db()
    assert alert.consecutive_count == 2


@pytest.mark.django_db
def test_repeated_failure_alert_escalation(monitor_factory, user1):
    mon = monitor_factory(owner=user1)
    fail_res = CheckResult.objects.create(
        monitor=mon,
        http_status_code=503,
        response_time_ms=100.0,
        outcome='failure',
        error_category='connection_failed',
        expected_status_codes='200',
        status_matched=False
    )
    mon.consecutive_failures = 3
    evaluate_monitor_alerts(mon, fail_res)

    alert = AlertEvent.objects.filter(monitor=mon, state='active').first()
    assert alert is not None
    assert alert.alert_type == AlertEvent.TYPE_REPEATED_FAILURE
    assert alert.severity == AlertEvent.SEVERITY_CRITICAL


@pytest.mark.django_db
def test_latency_threshold_alerts(monitor_factory, user1):
    mon = monitor_factory(owner=user1, latency_warning_threshold=300, latency_failure_threshold=1000)

    # Slow check (400ms > 300ms warning)
    warn_res = CheckResult.objects.create(
        monitor=mon,
        http_status_code=200,
        response_time_ms=400.0,
        outcome='success',
        expected_status_codes='200',
        status_matched=True
    )
    evaluate_monitor_alerts(mon, warn_res)

    alert = AlertEvent.objects.filter(monitor=mon, state='active').first()
    assert alert is not None
    assert alert.alert_type == AlertEvent.TYPE_LATENCY_WARNING
    assert alert.severity == AlertEvent.SEVERITY_WARNING


@pytest.mark.django_db
def test_recovery_resolves_active_alerts(monitor_factory, user1):
    mon = monitor_factory(owner=user1, latency_warning_threshold=500)

    # Active failure alert
    AlertEvent.objects.create(
        monitor=mon,
        alert_type=AlertEvent.TYPE_ENDPOINT_DOWN,
        severity=AlertEvent.SEVERITY_CRITICAL,
        state=AlertEvent.STATE_ACTIVE,
        description="Endpoint is down"
    )
    assert AlertEvent.objects.filter(monitor=mon, state='active').count() == 1

    # Healthy check succeeds
    good_res = CheckResult.objects.create(
        monitor=mon,
        http_status_code=200,
        response_time_ms=85.0,
        outcome='success',
        expected_status_codes='200',
        status_matched=True
    )
    evaluate_monitor_alerts(mon, good_res)

    # Previous active alert is now resolved!
    assert AlertEvent.objects.filter(monitor=mon, state='active').count() == 0
    # Recovery alert recorded
    recovery = AlertEvent.objects.filter(monitor=mon, alert_type=AlertEvent.TYPE_RECOVERY).first()
    assert recovery is not None
    assert recovery.state == AlertEvent.STATE_RESOLVED


@pytest.mark.django_db
def test_manual_alert_resolve_api(auth_client, monitor_factory, user1):
    mon = monitor_factory(owner=user1)
    alert = AlertEvent.objects.create(
        monitor=mon,
        alert_type=AlertEvent.TYPE_ENDPOINT_DOWN,
        severity=AlertEvent.SEVERITY_WARNING,
        state=AlertEvent.STATE_ACTIVE,
        description="Manual test alert"
    )

    resp = auth_client.post(f'/api/v1/alerts/{alert.id}/resolve/')
    assert resp.status_code == status.HTTP_200_OK
    assert resp.json()['state'] == 'resolved'

    alert.refresh_from_db()
    assert alert.state == 'resolved'
    assert alert.resolved_at is not None
