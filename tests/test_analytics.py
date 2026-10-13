import pytest
from datetime import timedelta
from django.utils import timezone
from checks.models import CheckResult
from analytics.services import (
    calculate_performance_summary,
    calculate_timeseries_latency,
    calculate_status_distribution
)


@pytest.mark.django_db
def test_analytics_empty_dataset(user1):
    summary = calculate_performance_summary(user1, time_range='24h')
    assert summary['total_checks'] == 0
    assert summary['success_rate'] == 0.0
    assert summary['avg_latency_ms'] == 0.0
    assert summary['p95_latency_ms'] == 0.0

    points = calculate_timeseries_latency(user1, time_range='24h')
    assert points == []

    dist = calculate_status_distribution(user1, time_range='24h')
    assert dist['2xx'] == 0
    assert dist['errors'] == 0


@pytest.mark.django_db
def test_analytics_metrics_calculation(monitor_factory, user1):
    mon = monitor_factory(owner=user1)

    # Create 10 mock check results with varied latencies
    latencies = [100.0, 120.0, 150.0, 180.0, 200.0, 250.0, 300.0, 400.0, 600.0, 1000.0]
    for i, lat in enumerate(latencies):
        outcome = 'success' if i < 8 else 'failure'
        status_code = 200 if i < 8 else 500
        CheckResult.objects.create(
            monitor=mon,
            http_status_code=status_code,
            response_time_ms=lat,
            outcome=outcome,
            expected_status_codes='200-299',
            status_matched=(outcome == 'success')
        )

    summary = calculate_performance_summary(user1, monitor_id=mon.id, time_range='24h')
    assert summary['total_checks'] == 10
    assert summary['success_checks'] == 8
    assert summary['failed_checks'] == 2
    assert summary['success_rate'] == 80.0
    assert summary['error_rate'] == 20.0
    assert summary['avg_latency_ms'] == 330.0
    assert summary['min_latency_ms'] == 100.0
    assert summary['max_latency_ms'] == 1000.0
    # p50 of sorted: index 4 -> 200.0
    assert summary['p50_latency_ms'] == 200.0
    # p95 of 10 items: index 8 -> 600.0
    assert summary['p95_latency_ms'] == 600.0


@pytest.mark.django_db
def test_analytics_user_data_isolation(monitor_factory, user1, user2):
    mon1 = monitor_factory(owner=user1, name="Alice Mon")
    mon2 = monitor_factory(owner=user2, name="Bob Mon")

    CheckResult.objects.create(monitor=mon1, response_time_ms=150.0, outcome='success', expected_status_codes='200')
    CheckResult.objects.create(monitor=mon2, response_time_ms=900.0, outcome='failure', expected_status_codes='200')

    alice_summary = calculate_performance_summary(user1)
    bob_summary = calculate_performance_summary(user2)

    assert alice_summary['total_checks'] == 1
    assert alice_summary['success_rate'] == 100.0
    assert alice_summary['avg_latency_ms'] == 150.0

    assert bob_summary['total_checks'] == 1
    assert bob_summary['success_rate'] == 0.0
    assert bob_summary['avg_latency_ms'] == 900.0


@pytest.mark.django_db
def test_analytics_time_range_filter(monitor_factory, user1):
    mon = monitor_factory(owner=user1)
    now = timezone.now()

    # Old check from 3 days ago
    old_check = CheckResult.objects.create(
        monitor=mon,
        response_time_ms=100.0,
        outcome='success',
        expected_status_codes='200'
    )
    old_check.created_at = now - timedelta(days=3)
    old_check.save()

    # Recent check from 10 minutes ago
    new_check = CheckResult.objects.create(
        monitor=mon,
        response_time_ms=250.0,
        outcome='success',
        expected_status_codes='200'
    )
    new_check.created_at = now - timedelta(minutes=10)
    new_check.save()

    # Range '1h': should only include new_check
    summary_1h = calculate_performance_summary(user1, time_range='1h')
    assert summary_1h['total_checks'] == 1
    assert summary_1h['avg_latency_ms'] == 250.0

    # Range '7d': should include both
    summary_7d = calculate_performance_summary(user1, time_range='7d')
    assert summary_7d['total_checks'] == 2
